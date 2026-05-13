//go:build lightspark

package handler

import (
	"context"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/btcnetwork"
	"github.com/lightsparkdev/spark/common/keys"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	transferpkg "github.com/lightsparkdev/spark/so/transfer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the dual-write helper that flips transfer_receivers rows from
// INITIATED to RECEIVER_CLAIM_PENDING atomically with the transfers.status
// flip to SENDER_KEY_TWEAKED. The helper is the load-bearing piece — every
// call site (commitSenderKeyTweaks, tweakKeysForCoopExit, revertClaimTransfer)
// delegates to it.

type dualWriteFixture struct {
	t      *testing.T
	ctx    context.Context
	client *ent.Client
	rng    *rand.ChaCha8
}

func newDualWriteFixture(t *testing.T) *dualWriteFixture {
	t.Helper()
	ctx, dbCtx := db.ConnectToTestPostgres(t)
	return &dualWriteFixture{
		t:      t,
		ctx:    ctx,
		client: dbCtx.Client,
		rng:    rand.NewChaCha8([32]byte{}),
	}
}

func (f *dualWriteFixture) newPubkey() keys.Public {
	return keys.MustGeneratePrivateKeyFromRand(f.rng).Public()
}

// makeTransferWithReceivers creates a transfer + N receiver rows at the given
// statuses. Returns the transfer plus the receiver rows in input order.
func (f *dualWriteFixture) makeTransferWithReceivers(receiverStatuses []st.TransferReceiverStatus) (*ent.Transfer, []*ent.TransferReceiver) {
	f.t.Helper()
	transfer, err := f.client.Transfer.Create().
		SetNetwork(btcnetwork.Regtest).
		SetType(st.TransferTypeTransfer).
		SetStatus(st.TransferStatusSenderKeyTweakPending).
		SetSenderIdentityPubkey(f.newPubkey()).
		SetReceiverIdentityPubkey(f.newPubkey()).
		SetTotalValue(1000).
		SetExpiryTime(time.Now().Add(24 * time.Hour)).
		Save(f.ctx)
	require.NoError(f.t, err)

	receivers := make([]*ent.TransferReceiver, 0, len(receiverStatuses))
	for _, s := range receiverStatuses {
		r, err := f.client.TransferReceiver.Create().
			SetTransferID(transfer.ID).
			SetIdentityPubkey(f.newPubkey()).
			SetStatus(s).
			SetTransferType(transfer.Type).
			Save(f.ctx)
		require.NoError(f.t, err)
		receivers = append(receivers, r)
	}
	return transfer, receivers
}

// reloadStatus returns the current status of the receiver row from the DB.
func (f *dualWriteFixture) reloadStatus(receiverID uuid.UUID) st.TransferReceiverStatus {
	f.t.Helper()
	r, err := f.client.TransferReceiver.Get(f.ctx, receiverID)
	require.NoError(f.t, err)
	return r.Status
}

// TestMarkReceiversClaimPending_OnlyUpdatesInitiated verifies that the helper
// only flips rows in INITIATED — rows in any later state are untouched. This
// is the idempotency property: re-running the helper on a partially-progressed
// transfer must not regress later receivers.
func TestMarkReceiversClaimPending_OnlyUpdatesInitiated(t *testing.T) {
	f := newDualWriteFixture(t)

	transfer, receivers := f.makeTransferWithReceivers([]st.TransferReceiverStatus{
		st.TransferReceiverStatusInitiated,  // -> RECEIVER_CLAIM_PENDING
		st.TransferReceiverStatusInitiated,  // -> RECEIVER_CLAIM_PENDING
		st.TransferReceiverStatusKeyTweaked, // unchanged (already past pending)
		st.TransferReceiverStatusCompleted,  // unchanged (terminal)
	})

	require.NoError(t, transferpkg.MarkReceiversClaimPending(f.ctx, f.client, transfer.ID))

	assert.Equal(t, st.TransferReceiverStatusReceiverClaimPending, f.reloadStatus(receivers[0].ID))
	assert.Equal(t, st.TransferReceiverStatusReceiverClaimPending, f.reloadStatus(receivers[1].ID))
	assert.Equal(t, st.TransferReceiverStatusKeyTweaked, f.reloadStatus(receivers[2].ID))
	assert.Equal(t, st.TransferReceiverStatusCompleted, f.reloadStatus(receivers[3].ID))
}

// TestMarkReceiversClaimPending_ScopedToTransfer verifies that the helper
// only updates rows belonging to the given transfer — receivers on other
// transfers are not touched even if they're in INITIATED.
func TestMarkReceiversClaimPending_ScopedToTransfer(t *testing.T) {
	f := newDualWriteFixture(t)

	transferA, receiversA := f.makeTransferWithReceivers([]st.TransferReceiverStatus{
		st.TransferReceiverStatusInitiated,
	})
	_, receiversB := f.makeTransferWithReceivers([]st.TransferReceiverStatus{
		st.TransferReceiverStatusInitiated,
	})

	require.NoError(t, transferpkg.MarkReceiversClaimPending(f.ctx, f.client, transferA.ID))

	assert.Equal(t, st.TransferReceiverStatusReceiverClaimPending, f.reloadStatus(receiversA[0].ID))
	assert.Equal(t, st.TransferReceiverStatusInitiated, f.reloadStatus(receiversB[0].ID),
		"receiver on a different transfer must NOT be touched")
}

// TestMarkReceiversClaimPending_Idempotent verifies that calling the helper
// twice is a no-op on the second call. Receivers already flipped to
// RECEIVER_CLAIM_PENDING by the first call must not be re-flipped or regressed.
func TestMarkReceiversClaimPending_Idempotent(t *testing.T) {
	f := newDualWriteFixture(t)

	transfer, receivers := f.makeTransferWithReceivers([]st.TransferReceiverStatus{
		st.TransferReceiverStatusInitiated,
		st.TransferReceiverStatusInitiated,
	})

	require.NoError(t, transferpkg.MarkReceiversClaimPending(f.ctx, f.client, transfer.ID))
	require.NoError(t, transferpkg.MarkReceiversClaimPending(f.ctx, f.client, transfer.ID))

	for _, r := range receivers {
		assert.Equal(t, st.TransferReceiverStatusReceiverClaimPending, f.reloadStatus(r.ID))
	}
}

// TestMarkReceiversClaimPending_MultiReceiverFlipsAll exercises the multi-
// receiver case explicitly: a single transfer with several INITIATED rows
// must transition them all in one call.
func TestMarkReceiversClaimPending_MultiReceiverFlipsAll(t *testing.T) {
	f := newDualWriteFixture(t)

	transfer, receivers := f.makeTransferWithReceivers([]st.TransferReceiverStatus{
		st.TransferReceiverStatusInitiated,
		st.TransferReceiverStatusInitiated,
		st.TransferReceiverStatusInitiated,
		st.TransferReceiverStatusInitiated,
		st.TransferReceiverStatusInitiated,
	})

	require.NoError(t, transferpkg.MarkReceiversClaimPending(f.ctx, f.client, transfer.ID))

	for i, r := range receivers {
		assert.Equal(t, st.TransferReceiverStatusReceiverClaimPending, f.reloadStatus(r.ID),
			"receiver %d should have flipped", i)
	}
}

// TestMarkReceiversClaimPending_NoMatchingRows verifies the helper is a no-op
// when no INITIATED rows exist for the transfer (e.g., already-progressed
// transfer or empty receiver set). Must not error.
func TestMarkReceiversClaimPending_NoMatchingRows(t *testing.T) {
	f := newDualWriteFixture(t)

	// Transfer with only post-pending receivers.
	transfer, receivers := f.makeTransferWithReceivers([]st.TransferReceiverStatus{
		st.TransferReceiverStatusKeyTweaked,
		st.TransferReceiverStatusKeyTweakLocked,
	})

	require.NoError(t, transferpkg.MarkReceiversClaimPending(f.ctx, f.client, transfer.ID))

	assert.Equal(t, st.TransferReceiverStatusKeyTweaked, f.reloadStatus(receivers[0].ID))
	assert.Equal(t, st.TransferReceiverStatusKeyTweakLocked, f.reloadStatus(receivers[1].ID))
}
