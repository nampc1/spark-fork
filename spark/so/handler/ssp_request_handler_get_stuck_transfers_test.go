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
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/knobs"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the GetStuckTransfers MIMO path. These drive the public RPC
// handler (not the internal queryMIMOStuckTransferIDs helper) so the tests
// survive refactors of the query shape as long as the handler contract
// holds.
//
// All tests use Postgres because the MIMO path's raw SQL relies on the
// partial indexes + pq.Array bindings, neither of which SQLite supports.

// stuckFixture is minimal test scaffolding — sets up ctx, a Postgres-backed
// Ent client, the MIMO knob, and the handler under test.
type stuckFixture struct {
	t       *testing.T
	ctx     context.Context
	client  *ent.Client
	handler *SspRequestHandler
	rng     *rand.ChaCha8
	baseNow time.Time // reference "now" for placing rows on the timeline
}

func newStuckFixture(t *testing.T) *stuckFixture {
	t.Helper()
	ctx, _ := db.ConnectToTestPostgres(t)
	client, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)

	ctx = knobs.InjectKnobsService(ctx, knobs.NewFixedKnobs(map[string]float64{
		knobs.KnobReadMIMODataModelGetStuckTransfers: 100,
	}))

	return &stuckFixture{
		t:       t,
		ctx:     ctx,
		client:  client,
		handler: NewSspRequestHandler(&so.Config{Identifier: "test-operator"}),
		rng:     rand.NewChaCha8([32]byte{}),
		baseNow: time.Now(),
	}
}

func (f *stuckFixture) newPubkey() keys.Public {
	return keys.MustGeneratePrivateKeyFromRand(f.rng).Public()
}

// transferOpts describes a fixture transfer. `transferState`, `sender`, and
// `receiver` are required. `receiverState` defaults to INITIATED.
// `createTime` defaults to 2h before the fixture's baseNow (safely inside
// the 1-hour `before` cutoff that GetStuckTransfers enforces).
// `receiverCreateTime` overrides the transfer_receivers.create_time for the
// primary receiver row when non-zero; otherwise edges inherit `createTime`.
// This simulates historical MIMO divergence where participant timestamps
// drifted from transfers.create_time.
type transferOpts struct {
	network            btcnetwork.Network
	transferState      st.TransferStatus
	sender             keys.Public
	receiver           keys.Public
	receiverState      st.TransferReceiverStatus
	extraReceivers     []extraReceiver
	createTime         time.Time
	receiverCreateTime time.Time
}

type extraReceiver struct {
	pubkey keys.Public
	status st.TransferReceiverStatus
}

// makeTransfer creates a Transfer plus one TransferSender and one or more
// TransferReceivers. This is fixture setup, not a public API — but there is
// no public "create transfer" entry point on SspRequestHandler that we can
// reach without wiring through the full transfer protocol. Ent builders are
// the minimum scaffolding; assertions still go through the handler RPC.
func (f *stuckFixture) makeTransfer(opts transferOpts) *ent.Transfer {
	f.t.Helper()
	network := opts.network
	if network == btcnetwork.Unspecified {
		network = btcnetwork.Regtest
	}
	createTime := opts.createTime
	if createTime.IsZero() {
		createTime = f.baseNow.Add(-2 * time.Hour)
	}
	receiverState := opts.receiverState
	if receiverState == "" {
		receiverState = st.TransferReceiverStatusSenderInitiated
	}

	transfer, err := f.client.Transfer.Create().
		SetNetwork(network).
		SetType(st.TransferTypeTransfer).
		SetStatus(opts.transferState).
		SetExpiryTime(f.baseNow.Add(24 * time.Hour)).
		SetTotalValue(1000).
		SetSenderIdentityPubkey(opts.sender).
		SetReceiverIdentityPubkey(opts.receiver).
		SetCreateTime(createTime).
		Save(f.ctx)
	require.NoError(f.t, err)

	_, err = f.client.TransferSender.Create().
		SetTransferID(transfer.ID).
		SetIdentityPubkey(opts.sender).
		SetCreateTime(createTime).
		Save(f.ctx)
	require.NoError(f.t, err)

	receiverCreateTime := opts.receiverCreateTime
	if receiverCreateTime.IsZero() {
		receiverCreateTime = createTime
	}
	_, err = f.client.TransferReceiver.Create().
		SetTransferID(transfer.ID).
		SetIdentityPubkey(opts.receiver).
		SetStatus(receiverState).
		SetCreateTime(receiverCreateTime).
		Save(f.ctx)
	require.NoError(f.t, err)

	for _, extra := range opts.extraReceivers {
		_, err := f.client.TransferReceiver.Create().
			SetTransferID(transfer.ID).
			SetIdentityPubkey(extra.pubkey).
			SetStatus(extra.status).
			SetCreateTime(createTime).
			Save(f.ctx)
		require.NoError(f.t, err)
	}
	return transfer
}

// getStuckTransferIDs invokes the handler and returns just the transfer IDs
// for concise assertions. `network` defaults to REGTEST if UNSPECIFIED, since
// all test fixtures default to Regtest.
func (f *stuckFixture) getStuckTransferIDs(user keys.Public, network pb.Network, limit, offset int64) []uuid.UUID {
	f.t.Helper()
	req := &pbssp.GetStuckTransfersRequest{
		UserIdentityPublicKey: user.Serialize(),
		Network:               network,
		Limit:                 limit,
		Offset:                offset,
	}
	resp, err := f.handler.GetStuckTransfers(f.ctx, req)
	require.NoError(f.t, err)
	ids := make([]uuid.UUID, 0, len(resp.Transfers))
	for _, st := range resp.Transfers {
		id, err := uuid.Parse(st.Transfer.Id)
		require.NoError(f.t, err)
		ids = append(ids, id)
	}
	return ids
}

// -----------------------------------------------------------------------------
// Core correctness
// -----------------------------------------------------------------------------

func TestGetStuckTransfers_MIMO_Empty(t *testing.T) {
	f := newStuckFixture(t)
	unrelated := f.newPubkey()

	ids := f.getStuckTransferIDs(unrelated, pb.Network_UNSPECIFIED, 50, 0)
	assert.Empty(t, ids)
}

func TestGetStuckTransfers_MIMO_ReceiverOnly(t *testing.T) {
	f := newStuckFixture(t)
	user := f.newPubkey()

	t1 := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusReceiverKeyTweaked,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusKeyTweaked,
	})
	t2 := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusReceiverRefundSigned,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusRefundSigned,
	})
	// Completed — must not appear.
	_ = f.makeTransfer(transferOpts{
		transferState: st.TransferStatusCompleted,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusCompleted,
	})

	ids := f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 50, 0)
	assert.ElementsMatch(t, []uuid.UUID{t1.ID, t2.ID}, ids)
}

func TestGetStuckTransfers_MIMO_SenderOnly(t *testing.T) {
	f := newStuckFixture(t)
	user := f.newPubkey()

	t1 := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusSenderInitiated,
		sender:        user,
		receiver:      f.newPubkey(),
	})
	t2 := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusSenderKeyTweakPending,
		sender:        user,
		receiver:      f.newPubkey(),
	})
	// Past sender-stuck — must not appear.
	_ = f.makeTransfer(transferOpts{
		transferState: st.TransferStatusSenderKeyTweaked,
		sender:        user,
		receiver:      f.newPubkey(),
	})

	ids := f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 50, 0)
	assert.ElementsMatch(t, []uuid.UUID{t1.ID, t2.ID}, ids)
}

func TestGetStuckTransfers_MIMO_BothSenderAndReceiver(t *testing.T) {
	f := newStuckFixture(t)
	user := f.newPubkey()

	senderStuck := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusSenderInitiated,
		sender:        user,
		receiver:      f.newPubkey(),
	})
	receiverStuck := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusReceiverKeyTweaked,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusKeyTweaked,
	})

	ids := f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 50, 0)
	assert.ElementsMatch(t, []uuid.UUID{senderStuck.ID, receiverStuck.ID}, ids)
}

// TestGetStuckTransfers_MIMO_SelfTransfer_ReceiverStuck is the regression
// test for the NOT EXISTS anti-join bug flagged in PR #6280 review. A self-
// transfer (user is both sender + receiver) whose `transfers.status` has
// advanced past the sender-stuck set should still be returned when the
// user's own receiver row is stuck.
func TestGetStuckTransfers_MIMO_SelfTransfer_ReceiverStuck(t *testing.T) {
	f := newStuckFixture(t)
	user := f.newPubkey()

	self := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusReceiverRefundSigned,
		sender:        user, // user is also a sender
		receiver:      user,
		receiverState: st.TransferReceiverStatusRefundSigned,
	})

	ids := f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 50, 0)
	assert.ElementsMatch(t, []uuid.UUID{self.ID}, ids,
		"self-transfer stuck on the receiver side must be returned; the NOT EXISTS anti-join used to swallow it")
}

// TestGetStuckTransfers_MIMO_InitiatedNotStuck codifies the intent that
// INITIATED receivers are waiting (not stuck) — the receiver partial's
// WHERE clause excludes INITIATED for that reason.
func TestGetStuckTransfers_MIMO_InitiatedNotStuck(t *testing.T) {
	f := newStuckFixture(t)
	user := f.newPubkey()

	_ = f.makeTransfer(transferOpts{
		transferState: st.TransferStatusSenderKeyTweaked,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusSenderInitiated, // == "INITIATED"
	})

	ids := f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 50, 0)
	assert.Empty(t, ids, "INITIATED receivers are waiting, not stuck")
}

// TestGetStuckTransfers_MIMO_MultiReceiver_PerReceiverSemantic codifies the
// MIMO V1 design intent from the PR #6280 review: stuck is per-receiver.
// Two users sharing a multi-receiver transfer see different results
// depending on their own receiver row's state.
func TestGetStuckTransfers_MIMO_MultiReceiver_PerReceiverSemantic(t *testing.T) {
	f := newStuckFixture(t)
	completed := f.newPubkey()
	stuck := f.newPubkey()

	t1 := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusReceiverKeyTweaked,
		sender:        f.newPubkey(),
		receiver:      completed,
		receiverState: st.TransferReceiverStatusCompleted,
		extraReceivers: []extraReceiver{
			{pubkey: stuck, status: st.TransferReceiverStatusKeyTweaked},
		},
	})

	completedIDs := f.getStuckTransferIDs(completed, pb.Network_UNSPECIFIED, 50, 0)
	assert.Empty(t, completedIDs, "a receiver already completed should not see the transfer as stuck, even when other receivers are")

	stuckIDs := f.getStuckTransferIDs(stuck, pb.Network_UNSPECIFIED, 50, 0)
	assert.ElementsMatch(t, []uuid.UUID{t1.ID}, stuckIDs)
}

// -----------------------------------------------------------------------------
// Filters
// -----------------------------------------------------------------------------

// makeTransferWithLeaf creates a fixture transfer AND its accompanying Tree
// + SigningKeyshare + TreeNode + TransferLeaf, which the handler's network
// filter requires via HasTransferLeavesWith(HasLeafWith(NetworkEQ)). Used
// only by network-filter tests; most tests use makeTransfer + UNSPECIFIED.
func (f *stuckFixture) makeTransferWithLeaf(opts transferOpts) *ent.Transfer {
	f.t.Helper()
	network := opts.network
	if network == btcnetwork.Unspecified {
		network = btcnetwork.Regtest
	}

	baseTxid := st.NewRandomTxIDForTesting(f.t)
	tree, err := f.client.Tree.Create().
		SetNetwork(network).
		SetOwnerIdentityPubkey(opts.sender).
		SetBaseTxid(baseTxid).
		SetVout(0).
		SetStatus(st.TreeStatusAvailable).
		Save(f.ctx)
	require.NoError(f.t, err)

	secret := keys.MustGeneratePrivateKeyFromRand(f.rng)
	keyshare, err := f.client.SigningKeyshare.Create().
		SetPublicShares(map[string]keys.Public{"key": secret.Public()}).
		SetStatus(st.KeyshareStatusAvailable).
		SetSecretShare(secret).
		SetPublicKey(f.newPubkey()).
		SetMinSigners(2).
		SetCoordinatorIndex(1).
		Save(f.ctx)
	require.NoError(f.t, err)

	leaf, err := f.client.TreeNode.Create().
		SetTree(tree).
		SetNetwork(network).
		SetValue(1000).
		SetStatus(st.TreeNodeStatusTransferLocked).
		SetVerifyingPubkey(f.newPubkey()).
		SetOwnerIdentityPubkey(opts.sender).
		SetOwnerSigningPubkey(f.newPubkey()).
		SetRawTx(createTestTxBytesWithIndex(f.t, 1000, 0)).
		SetVout(0).
		SetSigningKeyshare(keyshare).
		Save(f.ctx)
	require.NoError(f.t, err)

	// Build the transfer + sender/receiver rows via makeTransfer.
	opts.network = network
	transfer := f.makeTransfer(opts)

	_, err = f.client.TransferLeaf.Create().
		SetTransfer(transfer).
		SetLeaf(leaf).
		SetPreviousRefundTx(createTestTxBytes(f.t, 1001)).
		SetIntermediateRefundTx(createTestTxBytes(f.t, 1002)).
		Save(f.ctx)
	require.NoError(f.t, err)

	return transfer
}

// TestGetStuckTransfers_MIMO_NetworkFilter exercises the network filter
// end-to-end. Requires transfer_leaves fixtures because the handler's filter
// uses HasTransferLeavesWith(HasLeafWith(NetworkEQ(...))).
func TestGetStuckTransfers_MIMO_NetworkFilter(t *testing.T) {
	f := newStuckFixture(t)
	user := f.newPubkey()

	regtest := f.makeTransferWithLeaf(transferOpts{
		network:       btcnetwork.Regtest,
		transferState: st.TransferStatusReceiverKeyTweaked,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusKeyTweaked,
	})
	mainnet := f.makeTransferWithLeaf(transferOpts{
		network:       btcnetwork.Mainnet,
		transferState: st.TransferStatusReceiverKeyTweaked,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusKeyTweaked,
	})

	assert.ElementsMatch(t, []uuid.UUID{regtest.ID},
		f.getStuckTransferIDs(user, pb.Network_REGTEST, 50, 0))
	assert.ElementsMatch(t, []uuid.UUID{mainnet.ID},
		f.getStuckTransferIDs(user, pb.Network_MAINNET, 50, 0))
	assert.ElementsMatch(t, []uuid.UUID{regtest.ID, mainnet.ID},
		f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 50, 0),
		"UNSPECIFIED returns all networks")
}

// TestGetStuckTransfers_MIMO_BeforeCutoff verifies the `before` parameter is
// respected end-to-end. Drives via req.Before on the RPC, not by calling the
// helper with a different cutoff.
func TestGetStuckTransfers_MIMO_BeforeCutoff(t *testing.T) {
	f := newStuckFixture(t)
	user := f.newPubkey()

	old := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusReceiverKeyTweaked,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusKeyTweaked,
		createTime:    f.baseNow.Add(-3 * time.Hour),
	})
	recent := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusReceiverKeyTweaked,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusKeyTweaked,
		createTime:    f.baseNow.Add(-90 * time.Minute), // outside default 1h cutoff, inside 2h cutoff
	})

	// Default cutoff (now - 1h) picks up both.
	resp, err := f.handler.GetStuckTransfers(f.ctx, &pbssp.GetStuckTransfersRequest{
		UserIdentityPublicKey: user.Serialize(),
		Network:               pb.Network_UNSPECIFIED,
		Limit:                 50,
	})
	require.NoError(t, err)
	require.Len(t, resp.Transfers, 2)

	// Tighter cutoff (now - 2h) excludes the 90-minute-old row, leaving only the 3h-old.
	resp, err = f.handler.GetStuckTransfers(f.ctx, &pbssp.GetStuckTransfersRequest{
		UserIdentityPublicKey: user.Serialize(),
		Network:               pb.Network_UNSPECIFIED,
		Before:                timestamppb.New(f.baseNow.Add(-2 * time.Hour)),
		Limit:                 50,
	})
	require.NoError(t, err)
	require.Len(t, resp.Transfers, 1)
	assert.Equal(t, old.ID.String(), resp.Transfers[0].Transfer.Id)
	assert.NotEqual(t, recent.ID.String(), resp.Transfers[0].Transfer.Id)
}

// -----------------------------------------------------------------------------
// Ordering + pagination
// -----------------------------------------------------------------------------

func TestGetStuckTransfers_MIMO_OrderedByCreateTimeDesc(t *testing.T) {
	f := newStuckFixture(t)
	user := f.newPubkey()

	newest := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusReceiverKeyTweaked,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusKeyTweaked,
		createTime:    f.baseNow.Add(-70 * time.Minute),
	})
	middle := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusReceiverKeyTweaked,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusKeyTweaked,
		createTime:    f.baseNow.Add(-2 * time.Hour),
	})
	oldest := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusReceiverKeyTweaked,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusKeyTweaked,
		createTime:    f.baseNow.Add(-3 * time.Hour),
	})

	ids := f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 50, 0)
	assert.Equal(t, []uuid.UUID{newest.ID, middle.ID, oldest.ID}, ids)
}

// TestGetStuckTransfers_MIMO_Pagination exercises the per-arm
// `LIMIT = offset + limit` contract end-to-end. With distinct create_times,
// page1 + page2 must equal the combined top-N, in order and without overlap.
// This is the regression test for the pagination bug we hit during
// validation — per-arm `LIMIT = limit` (the bug) would have let page2 pick up
// rows that don't belong on page2.
func TestGetStuckTransfers_MIMO_Pagination(t *testing.T) {
	f := newStuckFixture(t)
	user := f.newPubkey()

	// 10 stuck transfers, one per minute going back from -70m.
	for i := range 10 {
		f.makeTransfer(transferOpts{
			transferState: st.TransferStatusReceiverKeyTweaked,
			sender:        f.newPubkey(),
			receiver:      user,
			receiverState: st.TransferReceiverStatusKeyTweaked,
			createTime:    f.baseNow.Add(-time.Duration(70+i) * time.Minute),
		})
	}

	page1 := f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 5, 0)
	page2 := f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 5, 5)
	combined := f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 10, 0)

	require.Len(t, page1, 5)
	require.Len(t, page2, 5)
	require.Len(t, combined, 10)
	assert.Equal(t, combined[:5], page1, "page1 matches first half of combined")
	assert.Equal(t, combined[5:], page2, "page2 matches second half of combined")

	seen := make(map[uuid.UUID]struct{}, 10)
	for _, id := range page1 {
		seen[id] = struct{}{}
	}
	for _, id := range page2 {
		_, dup := seen[id]
		assert.False(t, dup, "page2 must not overlap page1: id=%s", id)
	}
}

// TestGetStuckTransfers_MIMO_TieBreaker exercises the `(create_time DESC,
// id DESC)` tiebreaker. With tied create_times, ordering must be
// deterministic — higher transfer UUID first.
func TestGetStuckTransfers_MIMO_TieBreaker(t *testing.T) {
	f := newStuckFixture(t)
	user := f.newPubkey()
	tiedTime := f.baseNow.Add(-2 * time.Hour)

	tA := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusReceiverKeyTweaked,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusKeyTweaked,
		createTime:    tiedTime,
	})
	tB := f.makeTransfer(transferOpts{
		transferState: st.TransferStatusReceiverKeyTweaked,
		sender:        f.newPubkey(),
		receiver:      user,
		receiverState: st.TransferReceiverStatusKeyTweaked,
		createTime:    tiedTime,
	})

	ids := f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 50, 0)
	require.Len(t, ids, 2)

	first, second := tA.ID, tB.ID
	if tA.ID.String() < tB.ID.String() {
		first, second = tB.ID, tA.ID
	}
	assert.Equal(t, []uuid.UUID{first, second}, ids,
		"transfer_id DESC tiebreaker must return the higher UUID first")
}

// TestGetStuckTransfers_MIMO_DivergentCreateTimes exercises the correctness
// guarantee that step-1 ID ordering matches step-2 Ent load ordering even
// when transfer_receivers.create_time diverges from transfers.create_time.
// Historical MIMO data predating the write-path invariant (PR #6248) has
// this divergence; the receiver arm must order/paginate by
// transfers.create_time so the result set is stable regardless.
//
// Setup: three stuck receivers with transfers.create_time in order A > B > C
// (newest first) but transfer_receivers.create_time deliberately *reversed*
// (C_edge > B_edge > A_edge). If the query ordered by r.create_time, the
// returned order would be C, B, A — wrong. Ordering by t.create_time gives
// the correct A, B, C.
func TestGetStuckTransfers_MIMO_DivergentCreateTimes(t *testing.T) {
	f := newStuckFixture(t)
	user := f.newPubkey()

	newest := f.makeTransfer(transferOpts{
		transferState:      st.TransferStatusReceiverKeyTweaked,
		sender:             f.newPubkey(),
		receiver:           user,
		receiverState:      st.TransferReceiverStatusKeyTweaked,
		createTime:         f.baseNow.Add(-70 * time.Minute), // newest by t.create_time
		receiverCreateTime: f.baseNow.Add(-3 * time.Hour),    // oldest by r.create_time
	})
	middle := f.makeTransfer(transferOpts{
		transferState:      st.TransferStatusReceiverKeyTweaked,
		sender:             f.newPubkey(),
		receiver:           user,
		receiverState:      st.TransferReceiverStatusKeyTweaked,
		createTime:         f.baseNow.Add(-2 * time.Hour),
		receiverCreateTime: f.baseNow.Add(-2 * time.Hour),
	})
	oldest := f.makeTransfer(transferOpts{
		transferState:      st.TransferStatusReceiverKeyTweaked,
		sender:             f.newPubkey(),
		receiver:           user,
		receiverState:      st.TransferReceiverStatusKeyTweaked,
		createTime:         f.baseNow.Add(-3 * time.Hour),    // oldest by t.create_time
		receiverCreateTime: f.baseNow.Add(-70 * time.Minute), // newest by r.create_time
	})

	ids := f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 50, 0)
	assert.Equal(t, []uuid.UUID{newest.ID, middle.ID, oldest.ID}, ids,
		"ordering must track transfers.create_time, not transfer_receivers.create_time")

	// Pagination must also be stable under divergence.
	page1 := f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 2, 0)
	page2 := f.getStuckTransferIDs(user, pb.Network_UNSPECIFIED, 2, 2)
	assert.Equal(t, []uuid.UUID{newest.ID, middle.ID}, page1)
	assert.Equal(t, []uuid.UUID{oldest.ID}, page2)
}
