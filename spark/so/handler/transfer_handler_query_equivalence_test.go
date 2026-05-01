//go:build lightspark

package handler

import (
	"context"
	"encoding/hex"
	"math/rand/v2"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/btcnetwork"
	"github.com/lightsparkdev/spark/common/keys"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/authn"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/knobs"
	sparktesting "github.com/lightsparkdev/spark/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Equivalence tests for QueryPendingTransfers MIMO vs legacy paths.
//
// These tests are load-bearing for the safety of the
// KnobReadMIMODataModelQueryPendingTransfers RolloutRandom rollout strategy.
// Per-request randomness means a single caller polling repeatedly can land on
// EITHER path; if the paths returned semantically different results, callers
// would see flapping. These tests prove that for the production-relevant
// query shapes, both paths return the same set of transfer IDs, the same
// pagination offsets, and equivalent per-transfer projections.
//
// Query-shape legend (used in test names + the parent PR's perf table):
//   - R1: receiver participant, bare predicate (network-only filter on
//     transfers + identity_pubkey + status)
//   - R2: receiver participant + types filter (e.g. types=[SWAP])
//   - R3: receiver participant + transfer_id filter (singular lookup)
//   - S1: sender participant, bare predicate
//   - SR1: sender_or_receiver participant — the UNION ALL path
//
// Postgres-only: queryPendingTransfersMIMO uses raw SQL with pq.Array bindings
// and ANY($N::text[])/NOW() — neither supported by SQLite.

// equivFixture sets up shared state for equivalence tests: a Postgres-backed
// Ent client, an authenticated session for the queried wallet, the privacy
// knob enabled, and the handler under test.
type equivFixture struct {
	t       *testing.T
	ctx     context.Context
	client  *ent.Client
	cfg     *so.Config
	handler *TransferHandler
	rng     *rand.ChaCha8
	baseNow time.Time

	// Pubkeys built into the dataset.
	cold   keys.Public // wallet with 0 pending receiver-side
	light  keys.Public // wallet with a handful of pending receivers
	medium keys.Public // wallet with many pending receivers
	sender keys.Public // wallet with sender-side pending transfers
	both   keys.Public // wallet with both sender and receiver pending data
	other  keys.Public // unrelated wallet — no pending data anywhere

	// The transfer used by multi-receiver assertions.
	multiReceiverTransferID uuid.UUID
	multiReceiverPrimary    keys.Public // primary queried receiver
	multiReceiverExtra      keys.Public // second receiver on same transfer
}

func newEquivFixture(t *testing.T) *equivFixture {
	t.Helper()
	ctx, _ := db.ConnectToTestPostgres(t)
	client, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)

	cfg := sparktesting.TestConfig(t)
	cfg.AuthzEnforced = true

	f := &equivFixture{
		t:       t,
		ctx:     ctx,
		client:  client,
		cfg:     cfg,
		handler: NewTransferHandler(cfg),
		rng:     rand.NewChaCha8([32]byte{}),
		baseNow: time.Now(),
	}
	f.cold = f.newPubkey()
	f.light = f.newPubkey()
	f.medium = f.newPubkey()
	f.sender = f.newPubkey()
	f.both = f.newPubkey()
	f.other = f.newPubkey()
	return f
}

func (f *equivFixture) newPubkey() keys.Public {
	return keys.MustGeneratePrivateKeyFromRand(f.rng).Public()
}

// pendingPair pairs a transfers.status with a transfer_receivers.status that
// dual-write keeps consistent in production. Both legacy and MIMO consider
// the resulting transfer pending, so they should return equivalent results.
type pendingPair struct {
	transferStatus st.TransferStatus
	receiverStatus st.TransferReceiverStatus
}

// pendingPairs is the set of (transfer.status, receiver.status) combinations
// that show up in real pending-transfer traffic and are pending under BOTH
// the legacy and MIMO predicates. Each spans one of the 5 receiver-pending
// statuses.
//
// Post-Phase-4 dual-write contract (SP-2923): a transfer at SENDER_KEY_TWEAKED
// has its receiver(s) at RECEIVER_CLAIM_PENDING (sender done, receiver hasn't
// started claim). Legacy queryTransfers picks this up via t.status; MIMO
// picks it up via r.status. INITIATED is no longer in either path's pending
// set — it's the pre-tweak state, where the sender hasn't finished its
// handoff and the receiver cannot act.
var pendingPairs = []pendingPair{
	{st.TransferStatusSenderKeyTweaked, st.TransferReceiverStatusReceiverClaimPending},
	{st.TransferStatusReceiverKeyTweaked, st.TransferReceiverStatusKeyTweaked},
	{st.TransferStatusReceiverKeyTweakLocked, st.TransferReceiverStatusKeyTweakLocked},
	{st.TransferStatusReceiverKeyTweakApplied, st.TransferReceiverStatusKeyTweakApplied},
	{st.TransferStatusReceiverRefundSigned, st.TransferReceiverStatusRefundSigned},
}

type makeTransferOpts struct {
	network        btcnetwork.Network
	transferType   st.TransferType
	transferStatus st.TransferStatus
	sender         keys.Public
	receiver       keys.Public
	receiverStatus st.TransferReceiverStatus
	expiryTime     time.Time
	createTime     time.Time
	extraReceivers []extraReceiverEquiv
}

type extraReceiverEquiv struct {
	pubkey keys.Public
	status st.TransferReceiverStatus
}

// makeTransfer creates a transfer plus its sender and receiver edge rows,
// matching the production dual-write contract. createTime is propagated
// to all edge rows per the cross-participant create_time invariant.
func (f *equivFixture) makeTransfer(opts makeTransferOpts) *ent.Transfer {
	f.t.Helper()
	if opts.network == btcnetwork.Unspecified {
		opts.network = btcnetwork.Regtest
	}
	if opts.transferType == "" {
		opts.transferType = st.TransferTypeTransfer
	}
	if opts.expiryTime.IsZero() {
		// Sender-pending paths require expiry < now. Default to 24h in the
		// past so sender-pending fixtures qualify; receiver-side queries
		// don't filter on expiry, so this default is safe for both.
		opts.expiryTime = f.baseNow.Add(-24 * time.Hour)
	}
	if opts.createTime.IsZero() {
		opts.createTime = f.baseNow.Add(-2 * time.Hour)
	}
	if opts.receiverStatus == "" {
		opts.receiverStatus = st.TransferReceiverStatusSenderInitiated
	}

	transfer, err := f.client.Transfer.Create().
		SetNetwork(opts.network).
		SetType(opts.transferType).
		SetStatus(opts.transferStatus).
		SetExpiryTime(opts.expiryTime).
		SetTotalValue(1000).
		SetSenderIdentityPubkey(opts.sender).
		SetReceiverIdentityPubkey(opts.receiver).
		SetCreateTime(opts.createTime).
		Save(f.ctx)
	require.NoError(f.t, err)

	_, err = f.client.TransferSender.Create().
		SetTransferID(transfer.ID).
		SetIdentityPubkey(opts.sender).
		SetCreateTime(opts.createTime).
		Save(f.ctx)
	require.NoError(f.t, err)

	_, err = f.client.TransferReceiver.Create().
		SetTransferID(transfer.ID).
		SetIdentityPubkey(opts.receiver).
		SetStatus(opts.receiverStatus).
		SetCreateTime(opts.createTime).
		Save(f.ctx)
	require.NoError(f.t, err)

	for _, extra := range opts.extraReceivers {
		_, err := f.client.TransferReceiver.Create().
			SetTransferID(transfer.ID).
			SetIdentityPubkey(extra.pubkey).
			SetStatus(extra.status).
			SetCreateTime(opts.createTime).
			Save(f.ctx)
		require.NoError(f.t, err)
	}
	return transfer
}

// privacyEnabled installs WalletSetting rows so HasReadAccessToWallet falls
// through to the session check for these wallets. Required for the queried
// wallet so the access check actually runs (rather than being bypassed by
// "no privacy setting → public").
func (f *equivFixture) privacyEnabled(pubkeys ...keys.Public) {
	f.t.Helper()
	for _, pk := range pubkeys {
		_, err := f.client.WalletSetting.Create().
			SetOwnerIdentityPublicKey(pk).
			SetPrivateEnabled(true).
			Save(f.ctx)
		require.NoError(f.t, err)
	}
}

// ctxForWallet returns a context authenticated as the given pubkey with the
// knob set for the given path (legacy=0, MIMO=100). Other knobs are pinned
// to production-relevant values so the two paths are compared like-for-like.
func (f *equivFixture) ctxForWallet(viewer keys.Public, mimoKnob float64) context.Context {
	ctx := authn.InjectSessionForTests(f.ctx, hex.EncodeToString(viewer.Serialize()), 9999999999)
	return knobs.InjectKnobsService(ctx, knobs.NewFixedKnobs(map[string]float64{
		knobs.KnobPrivacyEnabled:                         100,
		knobs.KnobReadMIMODataModelQueryPendingTransfers: mimoKnob,
		knobs.KnobReadMIMODataModelQueryTransfers:        0,
		knobs.KnobFilterSSPCounterSwapAsTransfer:         0,
	}))
}

// setupEquivalenceData populates the fixture with the data shape required by
// the equivalence cases. Returns the slice of transfer IDs created (handy
// for subset checks) but most assertions just look at handler output.
func (f *equivFixture) setupEquivalenceData() {
	f.t.Helper()

	// Privacy-protected wallets — the access check actually runs against
	// these. Other wallets stay public so SSP-style internal queries still
	// work without session injection.
	f.privacyEnabled(f.cold, f.light, f.medium, f.sender, f.both)

	// light: 5 pending receivers, one per pending pair, all on REGTEST and
	// type TRANSFER, with create_time spread so ORDER BY DESC is meaningful.
	for i, p := range pendingPairs {
		f.makeTransfer(makeTransferOpts{
			transferStatus: p.transferStatus,
			receiverStatus: p.receiverStatus,
			sender:         f.newPubkey(),
			receiver:       f.light,
			createTime:     f.baseNow.Add(time.Duration(-30-i) * time.Minute),
		})
	}

	// medium: 20 pending receivers on REGTEST. Mixed pair selection gives
	// status diversity. Spread create_time across 20 distinct minutes.
	for i := range 20 {
		p := pendingPairs[i%len(pendingPairs)]
		f.makeTransfer(makeTransferOpts{
			transferStatus: p.transferStatus,
			receiverStatus: p.receiverStatus,
			sender:         f.newPubkey(),
			receiver:       f.medium,
			createTime:     f.baseNow.Add(time.Duration(-100-i) * time.Minute),
		})
	}

	// medium also has type variation — one transfer of each non-TRANSFER
	// pending type so the types-filter cases have something to match.
	for i, ttype := range []st.TransferType{st.TransferTypeSwap, st.TransferTypePreimageSwap, st.TransferTypePrimarySwapV3, st.TransferTypeCounterSwap} {
		f.makeTransfer(makeTransferOpts{
			transferType:   ttype,
			transferStatus: st.TransferStatusReceiverKeyTweaked,
			receiverStatus: st.TransferReceiverStatusKeyTweaked,
			sender:         f.newPubkey(),
			receiver:       f.medium,
			createTime:     f.baseNow.Add(time.Duration(-200-i) * time.Minute),
		})
	}

	// medium also gets a MAINNET pending transfer to exercise the network
	// filter (REGTEST queries must not return MAINNET rows).
	f.makeTransfer(makeTransferOpts{
		network:        btcnetwork.Mainnet,
		transferStatus: st.TransferStatusReceiverKeyTweaked,
		receiverStatus: st.TransferReceiverStatusKeyTweaked,
		sender:         f.newPubkey(),
		receiver:       f.medium,
		createTime:     f.baseNow.Add(-300 * time.Minute),
	})

	// medium: a COMPLETED transfer that must NOT show up as pending in
	// either path (sanity that exclusion still works).
	f.makeTransfer(makeTransferOpts{
		transferStatus: st.TransferStatusCompleted,
		receiverStatus: st.TransferReceiverStatusCompleted,
		sender:         f.newPubkey(),
		receiver:       f.medium,
		createTime:     f.baseNow.Add(-400 * time.Minute),
	})

	// sender: sender-pending transfers. Mix of expired (qualifies) and
	// not-yet-expired (excluded). Both paths apply expiry_time < NOW().
	for i, st0 := range []st.TransferStatus{st.TransferStatusSenderKeyTweakPending, st.TransferStatusSenderInitiated} {
		// Expired — qualifies as pending in both paths.
		f.makeTransfer(makeTransferOpts{
			transferStatus: st0,
			receiverStatus: st.TransferReceiverStatusSenderInitiated,
			sender:         f.sender,
			receiver:       f.newPubkey(),
			expiryTime:     f.baseNow.Add(-1 * time.Hour),
			createTime:     f.baseNow.Add(time.Duration(-50-i) * time.Minute),
		})
		// Not yet expired — must be excluded by both paths.
		f.makeTransfer(makeTransferOpts{
			transferStatus: st0,
			receiverStatus: st.TransferReceiverStatusSenderInitiated,
			sender:         f.sender,
			receiver:       f.newPubkey(),
			expiryTime:     f.baseNow.Add(24 * time.Hour),
			createTime:     f.baseNow.Add(time.Duration(-60-i) * time.Minute),
		})
	}

	// both: one transfer where `both` is the sender (sender-pending,
	// expired) and one where `both` is the receiver (receiver-pending).
	// Used by the sender_or_receiver cases.
	f.makeTransfer(makeTransferOpts{
		transferStatus: st.TransferStatusSenderKeyTweakPending,
		receiverStatus: st.TransferReceiverStatusSenderInitiated,
		sender:         f.both,
		receiver:       f.newPubkey(),
		expiryTime:     f.baseNow.Add(-1 * time.Hour),
		createTime:     f.baseNow.Add(-70 * time.Minute),
	})
	f.makeTransfer(makeTransferOpts{
		transferStatus: st.TransferStatusReceiverKeyTweaked,
		receiverStatus: st.TransferReceiverStatusKeyTweaked,
		sender:         f.newPubkey(),
		receiver:       f.both,
		createTime:     f.baseNow.Add(-80 * time.Minute),
	})
	// both: same pubkey on sender (column) AND receiver (edge) sides. SR1's
	// sender arm does NOT match this row (t.status = RECEIVER_KEY_TWEAKED is
	// not in PendingSenderStatuses); only the receiver arm matches. UNION ALL
	// dedup is not exercised here — and can't be, given the disjointness
	// invariant locked by TestPendingStatusesDisjoint in so/mimo.
	f.makeTransfer(makeTransferOpts{
		transferStatus: st.TransferStatusReceiverKeyTweaked,
		receiverStatus: st.TransferReceiverStatusKeyTweaked,
		sender:         f.both,
		receiver:       f.both,
		createTime:     f.baseNow.Add(-90 * time.Minute),
	})

	// Multi-receiver transfer: light is the primary queried receiver, the
	// extra receiver is a separate pubkey. Both receivers are in pending
	// states. This isolates the MarshalProto-vs-MarshalProtoForReceiver
	// divergence on multi-receiver shapes.
	f.multiReceiverPrimary = f.newPubkey()
	f.multiReceiverExtra = f.newPubkey()
	f.privacyEnabled(f.multiReceiverPrimary)
	multi := f.makeTransfer(makeTransferOpts{
		transferStatus: st.TransferStatusReceiverKeyTweaked,
		receiverStatus: st.TransferReceiverStatusKeyTweaked,
		sender:         f.newPubkey(),
		receiver:       f.multiReceiverPrimary,
		createTime:     f.baseNow.Add(-110 * time.Minute),
		extraReceivers: []extraReceiverEquiv{
			{pubkey: f.multiReceiverExtra, status: st.TransferReceiverStatusKeyTweaked},
		},
	})
	f.multiReceiverTransferID = multi.ID
}

// runBothPaths invokes QueryPendingTransfers twice on the same filter — once
// with the MIMO knob off (legacy queryTransfers) and once with it on
// (queryPendingTransfersMIMO). Returns both responses + errors.
func (f *equivFixture) runBothPaths(viewer keys.Public, filter *pb.TransferFilter) (legacyResp, mimoResp *pb.QueryTransfersResponse, legacyErr, mimoErr error) {
	f.t.Helper()
	ctxLegacy := f.ctxForWallet(viewer, 0)
	legacyResp, legacyErr = f.handler.QueryPendingTransfers(ctxLegacy, filter)

	ctxMIMO := f.ctxForWallet(viewer, 100)
	mimoResp, mimoErr = f.handler.QueryPendingTransfers(ctxMIMO, filter)
	return legacyResp, mimoResp, legacyErr, mimoErr
}

// transferIDsOf extracts the ordered transfer IDs from a response. nil-safe.
func transferIDsOf(resp *pb.QueryTransfersResponse) []string {
	if resp == nil {
		return nil
	}
	ids := make([]string, 0, len(resp.Transfers))
	for _, t := range resp.Transfers {
		ids = append(ids, t.Id)
	}
	return ids
}

// leafIDSetOf returns the sorted set of leaf-row IDs on a transfer proto,
// independent of order.
func leafIDSetOf(t *pb.Transfer) []string {
	ids := make([]string, 0, len(t.Leaves))
	for _, l := range t.Leaves {
		ids = append(ids, l.Leaf.Id)
	}
	sort.Strings(ids)
	return ids
}

// assertResultsEquivalent validates the equivalence contract between the
// legacy and MIMO paths for a single filter. The contract:
//   - errors agree (both nil or both non-nil with the same gRPC code)
//   - the ordered list of transfer IDs is identical
//   - the response Offset is identical
//   - per-transfer projection (Status, Type, Network) matches by ID
//   - per-transfer leaf-id sets match (ElementsMatch — order is undefined
//     across the two marshaling paths)
func assertResultsEquivalent(t *testing.T, name string, legacy, mimo *pb.QueryTransfersResponse, legacyErr, mimoErr error) {
	t.Helper()
	if legacyErr != nil || mimoErr != nil {
		assert.Equal(t, status.Code(legacyErr), status.Code(mimoErr),
			"%s: gRPC code mismatch (legacy=%v, mimo=%v)", name, legacyErr, mimoErr)
		// If both errored, no further comparison.
		if legacyErr != nil && mimoErr != nil {
			return
		}
		t.Fatalf("%s: only one path errored (legacy=%v, mimo=%v)", name, legacyErr, mimoErr)
	}

	legacyIDs := transferIDsOf(legacy)
	mimoIDs := transferIDsOf(mimo)
	if !assert.Equal(t, legacyIDs, mimoIDs, "%s: transfer ID order mismatch", name) {
		return
	}
	assert.Equal(t, legacy.Offset, mimo.Offset, "%s: response Offset mismatch", name)

	mimoByID := make(map[string]*pb.Transfer, len(mimo.Transfers))
	for _, t := range mimo.Transfers {
		mimoByID[t.Id] = t
	}
	for _, lt := range legacy.Transfers {
		mt, ok := mimoByID[lt.Id]
		require.True(t, ok, "%s: transfer %s in legacy response missing from MIMO", name, lt.Id)
		assert.Equal(t, lt.Status, mt.Status, "%s: transfer %s Status mismatch", name, lt.Id)
		assert.Equal(t, lt.Type, mt.Type, "%s: transfer %s Type mismatch", name, lt.Id)
		assert.Equal(t, lt.Network, mt.Network, "%s: transfer %s Network mismatch", name, lt.Id)
		assert.ElementsMatch(t, leafIDSetOf(lt), leafIDSetOf(mt),
			"%s: transfer %s leaf-id set mismatch (legacy uses MarshalProto, MIMO uses MarshalProtoForReceiver — single-receiver should be equivalent)", name, lt.Id)
	}
}

// receiverFilter is a test-helper for building a TransferFilter rooted at the
// receiver participant variant.
func receiverFilter(pubkey keys.Public) *pb.TransferFilter {
	return &pb.TransferFilter{
		Participant: &pb.TransferFilter_ReceiverIdentityPublicKey{
			ReceiverIdentityPublicKey: pubkey.Serialize(),
		},
		Network: pb.Network_REGTEST,
	}
}

func senderFilter(pubkey keys.Public) *pb.TransferFilter {
	return &pb.TransferFilter{
		Participant: &pb.TransferFilter_SenderIdentityPublicKey{
			SenderIdentityPublicKey: pubkey.Serialize(),
		},
		Network: pb.Network_REGTEST,
	}
}

func senderOrReceiverFilter(pubkey keys.Public) *pb.TransferFilter {
	return &pb.TransferFilter{
		Participant: &pb.TransferFilter_SenderOrReceiverIdentityPublicKey{
			SenderOrReceiverIdentityPublicKey: pubkey.Serialize(),
		},
		Network: pb.Network_REGTEST,
	}
}

// -----------------------------------------------------------------------------
// Table-driven equivalence cases.
// -----------------------------------------------------------------------------

func TestQueryPendingTransfers_Equivalence(t *testing.T) {
	if !sparktesting.PostgresTestsEnabled() {
		t.Skip("equivalence tests require Postgres (raw SQL uses pq.Array + ANY/NOW)")
	}
	f := newEquivFixture(t)
	f.setupEquivalenceData()

	// Pre-pick a real transfer ID for the singular cases. The light wallet
	// has 5 pending receivers — one per pendingPair; any will do.
	resp, err := f.handler.QueryPendingTransfers(f.ctxForWallet(f.light, 0), receiverFilter(f.light))
	require.NoError(t, err)
	require.NotEmpty(t, resp.Transfers, "fixture should produce light-pending transfers")
	lightTransferID := resp.Transfers[0].Id
	otherWalletTransferIDs := make([]string, 0, 3)
	for i, tr := range resp.Transfers {
		if i >= 3 {
			break
		}
		otherWalletTransferIDs = append(otherWalletTransferIDs, tr.Id)
	}

	cases := []struct {
		name   string
		viewer keys.Public
		filter *pb.TransferFilter
	}{
		// R1 — receiver bare + network
		{"R1_receiver_cold_pubkey", f.cold, receiverFilter(f.cold)},
		{"R1_receiver_light_pubkey", f.light, receiverFilter(f.light)},
		{"R1_receiver_medium_pubkey", f.medium, receiverFilter(f.medium)},

		// R2 — receiver + types
		{
			"R2_receiver_types_swap_only", f.medium,
			withTypes(receiverFilter(f.medium), pb.TransferType_SWAP),
		},
		{
			"R2_receiver_types_swap_family", f.medium,
			withTypes(receiverFilter(f.medium), pb.TransferType_SWAP, pb.TransferType_PREIMAGE_SWAP, pb.TransferType_PRIMARY_SWAP_V3),
		},
		{
			"R2_receiver_types_no_match", f.cold,
			withTypes(receiverFilter(f.cold), pb.TransferType_TRANSFER),
		},
		{
			"R2_receiver_types_counter_swap", f.medium,
			withTypes(receiverFilter(f.medium), pb.TransferType_COUNTER_SWAP),
		},

		// R3 — singular by transfer_id
		{
			"R3_singular_existing_pending", f.light,
			withTransferIDs(receiverFilter(f.light), lightTransferID),
		},
		{
			"R3_singular_nonexistent", f.light,
			withTransferIDs(receiverFilter(f.light), uuid.New().String()),
		},
		{
			"R3_singular_multiple_ids", f.light,
			withTransferIDs(receiverFilter(f.light), otherWalletTransferIDs...),
		},
		{
			"R3_singular_id_for_other_pubkey", f.cold,
			withTransferIDs(receiverFilter(f.cold), lightTransferID),
		},

		// S1 — sender bare
		{"S1_sender_bare", f.sender, senderFilter(f.sender)},
		{"S1_sender_no_pending_pubkey", f.cold, senderFilter(f.cold)},

		// SR1 — sender_or_receiver
		{"SR1_both_arms", f.both, senderOrReceiverFilter(f.both)},
		{"SR1_receiver_only_arm", f.light, senderOrReceiverFilter(f.light)},
		{"SR1_sender_only_arm", f.sender, senderOrReceiverFilter(f.sender)},
		{"SR1_neither_arm", f.other, senderOrReceiverFilter(f.other)},

		// Time / order / pagination
		{
			"TIME_created_after_excludes_old", f.medium,
			withCreatedAfter(receiverFilter(f.medium), f.baseNow.Add(-150*time.Minute)),
		},
		{
			"TIME_created_before_excludes_recent", f.medium,
			withCreatedBefore(receiverFilter(f.medium), f.baseNow.Add(-150*time.Minute)),
		},
		{
			"ORDER_ascending", f.medium,
			withOrder(receiverFilter(f.medium), pb.Order_ASCENDING),
		},
		{
			"PAGE_limit_below_count", f.medium,
			withLimitOffset(receiverFilter(f.medium), 2, 0),
		},
		{
			"PAGE_limit_above_count", f.cold,
			withLimitOffset(receiverFilter(f.cold), 100, 0),
		},
		{
			"PAGE_deep_offset", f.medium,
			withLimitOffset(receiverFilter(f.medium), 5, 10),
		},
		{
			"PAGE_offset_past_end", f.medium,
			withLimitOffset(receiverFilter(f.medium), 5, 1000),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legacy, mimo, lerr, merr := f.runBothPaths(tc.viewer, tc.filter)
			assertResultsEquivalent(t, tc.name, legacy, mimo, lerr, merr)
		})
	}
}

// -----------------------------------------------------------------------------
// Access-check equivalence
// -----------------------------------------------------------------------------

// Privacy on + session matches → both paths return rows.
// Privacy on + session mismatch → both paths return empty (Offset=-1).
// Privacy on + no session → both paths return empty (Offset=-1).

func TestQueryPendingTransfers_Equivalence_Access_SessionMatches(t *testing.T) {
	if !sparktesting.PostgresTestsEnabled() {
		t.Skip("equivalence tests require Postgres")
	}
	f := newEquivFixture(t)
	f.setupEquivalenceData()

	legacy, mimo, lerr, merr := f.runBothPaths(f.light, receiverFilter(f.light))
	assertResultsEquivalent(t, "access_session_matches", legacy, mimo, lerr, merr)
	assert.NotEmpty(t, legacy.Transfers, "expected non-empty result when session matches")
}

func TestQueryPendingTransfers_Equivalence_Access_SessionMismatch(t *testing.T) {
	if !sparktesting.PostgresTestsEnabled() {
		t.Skip("equivalence tests require Postgres")
	}
	f := newEquivFixture(t)
	f.setupEquivalenceData()

	// Authenticate as `other`, query for `light`. Privacy is on for `light`,
	// so the access check must reject and both paths must return empty.
	ctxLegacy := f.ctxForWallet(f.other, 0)
	respLegacy, errLegacy := f.handler.QueryPendingTransfers(ctxLegacy, receiverFilter(f.light))
	ctxMIMO := f.ctxForWallet(f.other, 100)
	respMIMO, errMIMO := f.handler.QueryPendingTransfers(ctxMIMO, receiverFilter(f.light))

	assertResultsEquivalent(t, "access_session_mismatch", respLegacy, respMIMO, errLegacy, errMIMO)
	assert.Empty(t, respLegacy.Transfers, "expected empty result on session mismatch")
	assert.Equal(t, int64(-1), respLegacy.Offset, "expected Offset=-1 on session mismatch")
}

func TestQueryPendingTransfers_Equivalence_Access_NoSession(t *testing.T) {
	if !sparktesting.PostgresTestsEnabled() {
		t.Skip("equivalence tests require Postgres")
	}
	f := newEquivFixture(t)
	f.setupEquivalenceData()

	noSessionKnobs := knobs.NewFixedKnobs(map[string]float64{
		knobs.KnobPrivacyEnabled:                         100,
		knobs.KnobReadMIMODataModelQueryPendingTransfers: 0,
		knobs.KnobReadMIMODataModelQueryTransfers:        0,
		knobs.KnobFilterSSPCounterSwapAsTransfer:         0,
	})
	ctxLegacy := knobs.InjectKnobsService(f.ctx, noSessionKnobs)
	respLegacy, errLegacy := f.handler.QueryPendingTransfers(ctxLegacy, receiverFilter(f.light))

	mimoKnobs := knobs.NewFixedKnobs(map[string]float64{
		knobs.KnobPrivacyEnabled:                         100,
		knobs.KnobReadMIMODataModelQueryPendingTransfers: 100,
		knobs.KnobReadMIMODataModelQueryTransfers:        0,
		knobs.KnobFilterSSPCounterSwapAsTransfer:         0,
	})
	ctxMIMO := knobs.InjectKnobsService(f.ctx, mimoKnobs)
	respMIMO, errMIMO := f.handler.QueryPendingTransfers(ctxMIMO, receiverFilter(f.light))

	assertResultsEquivalent(t, "access_no_session", respLegacy, respMIMO, errLegacy, errMIMO)
	assert.Empty(t, respLegacy.Transfers, "expected empty result with no session + privacy enabled")
}

// -----------------------------------------------------------------------------
// Multi-receiver: highlight the MarshalProto vs MarshalProtoForReceiver split.
// -----------------------------------------------------------------------------

// TestQueryPendingTransfers_Equivalence_MultiReceiver verifies that for a
// multi-receiver transfer queried by one of its receivers, both paths return
// the same transfer ID — but the per-leaf projection MAY differ if the
// transfer has leaves, since legacy uses MarshalProto (all leaves) and MIMO
// uses MarshalProtoForReceiver (just the queried receiver's leaves).
//
// In MIMO MVP single-receiver this divergence is hidden because each transfer
// has at most one receiver edge. The fixture under test deliberately includes
// a multi-receiver transfer with NO leaves so the single-call equivalence
// (transfer ID, status, type, network) holds. If/when multi-receiver
// transfers carry receiver-tagged leaves in production, this assertion will
// surface the divergence loudly.
func TestQueryPendingTransfers_Equivalence_MultiReceiver(t *testing.T) {
	if !sparktesting.PostgresTestsEnabled() {
		t.Skip("equivalence tests require Postgres")
	}
	f := newEquivFixture(t)
	f.setupEquivalenceData()

	legacy, mimo, lerr, merr := f.runBothPaths(f.multiReceiverPrimary, receiverFilter(f.multiReceiverPrimary))
	assertResultsEquivalent(t, "multi_receiver_primary", legacy, mimo, lerr, merr)

	// Sanity: the multi-receiver transfer is in both responses.
	require.Len(t, legacy.Transfers, 1)
	require.Len(t, mimo.Transfers, 1)
	assert.Equal(t, f.multiReceiverTransferID.String(), legacy.Transfers[0].Id)
	assert.Equal(t, f.multiReceiverTransferID.String(), mimo.Transfers[0].Id)
}

// -----------------------------------------------------------------------------
// Pagination consistency across knob states
// -----------------------------------------------------------------------------

// TestQueryPendingTransfers_Equivalence_PaginationCrossKnob proves that the
// RolloutRandom rollout strategy is safe: a caller that pages with knob=0
// (legacy) and then again with knob=100 (MIMO) sees no overlap, no drops,
// and the union equals a single full-page call.
//
// This is the load-bearing check for the per-request randomness in
// QueryPendingTransfers. If this test ever fails, the routing must be
// tightened (e.g. always-on or always-off, deterministic per-caller).
func TestQueryPendingTransfers_Equivalence_PaginationCrossKnob(t *testing.T) {
	if !sparktesting.PostgresTestsEnabled() {
		t.Skip("equivalence tests require Postgres")
	}
	f := newEquivFixture(t)
	f.setupEquivalenceData()

	const pageSize = 5

	// Single full-page query (limit=10, offset=0) under the legacy path —
	// canonical reference for the union of two halves.
	full, err := f.handler.QueryPendingTransfers(
		f.ctxForWallet(f.medium, 0),
		withLimitOffset(receiverFilter(f.medium), 2*pageSize, 0),
	)
	require.NoError(t, err)
	require.Len(t, full.Transfers, 2*pageSize, "fixture should provide at least 10 medium-pending transfers")
	fullIDs := transferIDsOf(full)

	// Page 1 under legacy.
	page1, err := f.handler.QueryPendingTransfers(
		f.ctxForWallet(f.medium, 0),
		withLimitOffset(receiverFilter(f.medium), pageSize, 0),
	)
	require.NoError(t, err)
	page1IDs := transferIDsOf(page1)

	// Page 2 under MIMO. RolloutRandom would let this happen for the same
	// caller polling repeatedly; the contract must hold across paths.
	page2, err := f.handler.QueryPendingTransfers(
		f.ctxForWallet(f.medium, 100),
		withLimitOffset(receiverFilter(f.medium), pageSize, pageSize),
	)
	require.NoError(t, err)
	page2IDs := transferIDsOf(page2)

	assert.Equal(t, fullIDs[:pageSize], page1IDs, "page 1 (legacy) does not match first half of full page")
	assert.Equal(t, fullIDs[pageSize:], page2IDs, "page 2 (MIMO) does not match second half of full page")

	// And the reverse direction — page1 MIMO + page2 legacy.
	page1Mimo, err := f.handler.QueryPendingTransfers(
		f.ctxForWallet(f.medium, 100),
		withLimitOffset(receiverFilter(f.medium), pageSize, 0),
	)
	require.NoError(t, err)
	page2Legacy, err := f.handler.QueryPendingTransfers(
		f.ctxForWallet(f.medium, 0),
		withLimitOffset(receiverFilter(f.medium), pageSize, pageSize),
	)
	require.NoError(t, err)
	assert.Equal(t, fullIDs[:pageSize], transferIDsOf(page1Mimo), "page 1 (MIMO) does not match first half of full page (reverse direction)")
	assert.Equal(t, fullIDs[pageSize:], transferIDsOf(page2Legacy), "page 2 (legacy) does not match second half of full page (reverse direction)")
}

// -----------------------------------------------------------------------------
// Cross-knob pagination — one helper, three coverage extensions
// -----------------------------------------------------------------------------

// crossKnobPaginationCheck verifies page-by-page pagination is consistent
// across knob flips. For each page index, both knob=0 (legacy) and knob=100
// (MIMO) must return the same window of transfer IDs as the corresponding
// slice of a single full-sweep call under legacy. This load-bearing
// property is what RolloutRandom relies on — a caller that pages with the
// knob flipping between requests must see no overlap and no drops.
//
// Caller is responsible for ensuring `viewer` has at least
// pageSize*pageCount qualifying pending transfers under `filter`.
func (f *equivFixture) crossKnobPaginationCheck(t *testing.T, viewer keys.Public, filter *pb.TransferFilter, pageSize, pageCount int) {
	t.Helper()

	full, err := f.handler.QueryPendingTransfers(
		f.ctxForWallet(viewer, 0),
		withLimitOffset(filter, int64(pageSize*pageCount), 0),
	)
	require.NoError(t, err)
	require.Lenf(t, full.Transfers, pageSize*pageCount,
		"fixture must produce >= %d pending transfers for cross-knob pagination", pageSize*pageCount)
	fullIDs := transferIDsOf(full)

	for page := range pageCount {
		offset := int64(page * pageSize)
		expected := fullIDs[page*pageSize : (page+1)*pageSize]

		for _, kb := range []struct {
			knob  float64
			label string
		}{{0, "legacy"}, {100, "MIMO"}} {
			resp, err := f.handler.QueryPendingTransfers(
				f.ctxForWallet(viewer, kb.knob),
				withLimitOffset(filter, int64(pageSize), offset),
			)
			require.NoErrorf(t, err, "page %d (%s)", page, kb.label)
			assert.Equalf(t, expected, transferIDsOf(resp),
				"page %d (%s): pagination window does not match the full-sweep reference",
				page, kb.label)
		}
	}
}

// TestQueryPendingTransfers_Equivalence_PaginationCrossKnob_Ascending locks
// the C3 fix (matching secondary id sort direction) across the knob flip.
// The within-knob ORDER_ascending case in the table-driven suite passes
// only because the fixture spreads create_time across distinct minutes;
// this test exercises the cross-knob pagination handoff in ASC mode.
func TestQueryPendingTransfers_Equivalence_PaginationCrossKnob_Ascending(t *testing.T) {
	if !sparktesting.PostgresTestsEnabled() {
		t.Skip("equivalence tests require Postgres")
	}
	f := newEquivFixture(t)
	f.setupEquivalenceData()

	f.crossKnobPaginationCheck(t, f.medium,
		withOrder(receiverFilter(f.medium), pb.Order_ASCENDING), 5, 2)
}

// TestQueryPendingTransfers_Equivalence_PaginationCrossKnob_Sender locks
// cross-knob pagination on the participant=Sender path. The PR's audit
// confirmed no internal callers, but external SDK callers may pass
// participant=Sender, so this path needs the same RolloutRandom safety
// guarantees as Receiver and SenderOrReceiver.
//
// Uses a dedicated pubkey with 10 pending senders (the shared fixture's
// f.sender only has 2, insufficient for 2 pages of 5).
func TestQueryPendingTransfers_Equivalence_PaginationCrossKnob_Sender(t *testing.T) {
	if !sparktesting.PostgresTestsEnabled() {
		t.Skip("equivalence tests require Postgres")
	}
	f := newEquivFixture(t)
	f.setupEquivalenceData()

	sender := f.newPubkey()
	f.privacyEnabled(sender)
	for i := range 10 {
		status := st.TransferStatusSenderKeyTweakPending
		if i%2 == 1 {
			status = st.TransferStatusSenderInitiated
		}
		f.makeTransfer(makeTransferOpts{
			transferStatus: status,
			receiverStatus: st.TransferReceiverStatusSenderInitiated,
			sender:         sender,
			receiver:       f.newPubkey(),
			expiryTime:     f.baseNow.Add(-1 * time.Hour),
			createTime:     f.baseNow.Add(time.Duration(-500-i) * time.Minute),
		})
	}

	f.crossKnobPaginationCheck(t, sender, senderFilter(sender), 5, 2)
}

// TestQueryPendingTransfers_Equivalence_PaginationCrossKnob_SR1_DeepOffset
// locks cross-knob pagination on the participant=SenderOrReceiver path at
// 3 pages of size 5 (offset reaches 10). This exercises the
// perArmLimit = offset+limit math in buildPendingIDsQuerySenderOrReceiver
// — at offset=10 each arm must walk far enough that the merged stream has
// 15 candidates available.
//
// Uses a dedicated pubkey with 8 sender-pending + 8 receiver-pending = 16
// total (perArmLimit=15 in the deepest page).
func TestQueryPendingTransfers_Equivalence_PaginationCrossKnob_SR1_DeepOffset(t *testing.T) {
	if !sparktesting.PostgresTestsEnabled() {
		t.Skip("equivalence tests require Postgres")
	}
	f := newEquivFixture(t)
	f.setupEquivalenceData()

	sr := f.newPubkey()
	f.privacyEnabled(sr)

	// Sender-pending half — alternating SENDER_KEY_TWEAK_PENDING / SENDER_INITIATED.
	for i := range 8 {
		status := st.TransferStatusSenderKeyTweakPending
		if i%2 == 1 {
			status = st.TransferStatusSenderInitiated
		}
		f.makeTransfer(makeTransferOpts{
			transferStatus: status,
			receiverStatus: st.TransferReceiverStatusSenderInitiated,
			sender:         sr,
			receiver:       f.newPubkey(),
			expiryTime:     f.baseNow.Add(-1 * time.Hour),
			createTime:     f.baseNow.Add(time.Duration(-700-i) * time.Minute),
		})
	}

	// Receiver-pending half — varied across pendingPairs.
	for i := range 8 {
		pair := pendingPairs[i%len(pendingPairs)]
		f.makeTransfer(makeTransferOpts{
			transferStatus: pair.transferStatus,
			receiverStatus: pair.receiverStatus,
			sender:         f.newPubkey(),
			receiver:       sr,
			createTime:     f.baseNow.Add(time.Duration(-800-i) * time.Minute),
		})
	}

	f.crossKnobPaginationCheck(t, sr, senderOrReceiverFilter(sr), 5, 3)
}

// -----------------------------------------------------------------------------
// Tied-create_time ordering — the step-2 ent secondary-sort regression test
// -----------------------------------------------------------------------------

// TestQueryPendingTransfers_Equivalence_TiedCreateTime asserts that when
// multiple pending transfers share an identical create_time, the MIMO path
// returns them in a direction-consistent secondary order:
//
//	ASC  → (create_time ASC,  id ASC)
//	DESC → (create_time DESC, id DESC)
//
// This is the contract the step-1 raw SQL produces; step-2 ent must preserve
// it. Pre-fix, step-2 hardcoded id DESC for both directions, so ASC mode
// would silently reverse tied-row order across the knob flip.
//
// Legacy queryTransfers has no secondary sort on id; its behavior on ties is
// Postgres-native (heap order, indeterminate). This test asserts MIMO
// self-consistency (DESC == reverse(ASC)) and SET-equivalence with legacy —
// NOT order-equivalence with legacy on ties.
//
// This asymmetry is intentional and pre-existing: legacy has been
// non-deterministic on ties in production for as long as queryTransfers has
// existed; MIMO is strictly better. Across knob flips during the ramp, a
// caller polling tied rows could see them reorder between requests — that's
// a known acknowledged consequence of replacing a non-deterministic path
// with a deterministic one, not a regression introduced by this PR.
//
// Future editors: do NOT tighten the legacy assertion to order-equivalence
// without first adding a tiebreaker to queryTransfers' ORDER BY (and
// re-validating the full legacy perf table — the R1 stuck-user case is the
// cardinality regime most at risk of plan-shape change from a new sort
// column).
func TestQueryPendingTransfers_Equivalence_TiedCreateTime(t *testing.T) {
	if !sparktesting.PostgresTestsEnabled() {
		t.Skip("equivalence tests require Postgres")
	}
	f := newEquivFixture(t)

	// Dedicated pubkey — no contamination from setupEquivalenceData.
	receiver := f.newPubkey()
	f.privacyEnabled(receiver)

	// 5 transfers sharing the exact same create_time and same pending pair.
	const tieCount = 5
	tieTime := f.baseNow.Add(-2 * time.Hour)
	for range tieCount {
		f.makeTransfer(makeTransferOpts{
			transferStatus: st.TransferStatusReceiverKeyTweaked,
			receiverStatus: st.TransferReceiverStatusKeyTweaked,
			sender:         f.newPubkey(),
			receiver:       receiver,
			createTime:     tieTime,
		})
	}

	mimoCtx := f.ctxForWallet(receiver, 100)
	legacyCtx := f.ctxForWallet(receiver, 0)

	respASC, err := f.handler.QueryPendingTransfers(mimoCtx, withOrder(receiverFilter(receiver), pb.Order_ASCENDING))
	require.NoError(t, err)
	require.Len(t, respASC.Transfers, tieCount)
	idsASC := transferIDsOf(respASC)

	respDESC, err := f.handler.QueryPendingTransfers(mimoCtx, withOrder(receiverFilter(receiver), pb.Order_DESCENDING))
	require.NoError(t, err)
	require.Len(t, respDESC.Transfers, tieCount)
	idsDESC := transferIDsOf(respDESC)

	// MIMO must be self-consistent across order direction on ties.
	reversed := make([]string, len(idsASC))
	for i, id := range idsASC {
		reversed[len(idsASC)-1-i] = id
	}
	assert.Equal(t, idsDESC, reversed,
		"MIMO DESC must be the exact reverse of MIMO ASC on tied-create_time rows; pre-fix, step-2 hardcoded id DESC for both directions and reversed tied-row order in ASC mode")

	// MIMO ASC ties must come back in id ASC order (the step-1 SQL contract).
	asciiSortedASC := make([]string, len(idsASC))
	copy(asciiSortedASC, idsASC)
	sort.Strings(asciiSortedASC)
	assert.Equal(t, asciiSortedASC, idsASC,
		"MIMO ASC must return tied rows in id ASC order")

	// SET-equivalence with legacy on ties (order may differ — legacy has no
	// secondary sort).
	respLegacyDESC, err := f.handler.QueryPendingTransfers(legacyCtx, receiverFilter(receiver))
	require.NoError(t, err)
	legacyIDs := transferIDsOf(respLegacyDESC)
	require.Len(t, legacyIDs, tieCount)
	assert.ElementsMatch(t, legacyIDs, idsDESC,
		"legacy and MIMO must return the same SET of pending transfers on tied-create_time rows; only intra-tie order may differ")
}

// -----------------------------------------------------------------------------
// Filter builders
// -----------------------------------------------------------------------------

func withTypes(filter *pb.TransferFilter, types ...pb.TransferType) *pb.TransferFilter {
	filter.Types = types
	return filter
}

func withTransferIDs(filter *pb.TransferFilter, ids ...string) *pb.TransferFilter {
	filter.TransferIds = ids
	return filter
}

func withCreatedAfter(filter *pb.TransferFilter, ts time.Time) *pb.TransferFilter {
	filter.TimeFilter = &pb.TransferFilter_CreatedAfter{
		CreatedAfter: timestamppb.New(ts),
	}
	return filter
}

func withCreatedBefore(filter *pb.TransferFilter, ts time.Time) *pb.TransferFilter {
	filter.TimeFilter = &pb.TransferFilter_CreatedBefore{
		CreatedBefore: timestamppb.New(ts),
	}
	return filter
}

func withOrder(filter *pb.TransferFilter, order pb.Order) *pb.TransferFilter {
	filter.Order = order
	return filter
}

func withLimitOffset(filter *pb.TransferFilter, limit, offset int64) *pb.TransferFilter {
	filter.Limit = limit
	filter.Offset = offset
	return filter
}
