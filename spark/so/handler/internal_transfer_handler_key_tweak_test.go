//go:build lightspark

package handler

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/btcnetwork"
	"github.com/lightsparkdev/spark/common/keys"
	sparkProto "github.com/lightsparkdev/spark/proto/spark"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	enttransferleaf "github.com/lightsparkdev/spark/so/ent/transferleaf"
	sparktesting "github.com/lightsparkdev/spark/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// TestSettleSenderKeyTweak_Commit_EmptyKeyTweak verifies that committing
// a transfer via SettleSenderKeyTweak fails when a TransferLeaf has no
// key_tweak stored, rather than allowing proto.Unmarshal on empty bytes.
//
// This tests defense-in-depth: the empty key_tweak state shouldn't be
// reachable through normal operation, but if it is (due to a bug or race),
// the system should fail fast with a clear error.
func TestSettleSenderKeyTweak_Commit_EmptyKeyTweak(t *testing.T) {
	ctx, dbCtx := db.ConnectToTestPostgres(t)
	cfg := sparktesting.TestConfig(t)
	rng := rand.NewChaCha8([32]byte{44})

	senderPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	receiverPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)

	client := dbCtx.Client

	keysharePrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	publicSharePrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	signingKeyshare, err := client.SigningKeyshare.Create().
		SetStatus(st.KeyshareStatusAvailable).
		SetSecretShare(keysharePrivKey).
		SetPublicShares(map[string]keys.Public{"test": publicSharePrivKey.Public()}).
		SetPublicKey(keysharePrivKey.Public()).
		SetMinSigners(2).
		SetCoordinatorIndex(0).
		Save(ctx)
	require.NoError(t, err)

	tree, err := client.Tree.Create().
		SetStatus(st.TreeStatusAvailable).
		SetNetwork(btcnetwork.Regtest).
		SetOwnerIdentityPubkey(senderPrivKey.Public()).
		SetBaseTxid(st.NewRandomTxIDForTesting(t)).
		SetVout(0).
		Save(ctx)
	require.NoError(t, err)

	verifyingPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerSigningPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	leaf, err := client.TreeNode.Create().
		SetStatus(st.TreeNodeStatusAvailable).
		SetTree(tree).
		SetNetwork(tree.Network).
		SetSigningKeyshare(signingKeyshare).
		SetValue(1000).
		SetVerifyingPubkey(verifyingPrivKey.Public()).
		SetOwnerIdentityPubkey(senderPrivKey.Public()).
		SetOwnerSigningPubkey(ownerSigningPrivKey.Public()).
		SetRawTx(createTestTxBytes(t, 3000)).
		SetRawRefundTx(createTestTxBytes(t, 3100)).
		SetVout(0).
		Save(ctx)
	require.NoError(t, err)

	// Create transfer in SenderKeyTweakPending status — the state that
	// commitSenderKeyTweaks expects to find.
	transfer, err := client.Transfer.Create().
		SetNetwork(btcnetwork.Regtest).
		SetStatus(st.TransferStatusSenderKeyTweakPending).
		SetType(st.TransferTypeTransfer).
		SetSenderIdentityPubkey(senderPrivKey.Public()).
		SetReceiverIdentityPubkey(receiverPrivKey.Public()).
		SetTotalValue(1000).
		SetExpiryTime(time.Now().Add(24 * time.Hour)).
		Save(ctx)
	require.NoError(t, err)

	// Create TransferLeaf with NO key_tweak set (simulates the inconsistent
	// state that this defense-in-depth check guards against).
	_, err = client.TransferLeaf.Create().
		SetTransfer(transfer).
		SetLeaf(leaf).
		SetPreviousRefundTx(createTestTxBytes(t, 4000)).
		SetIntermediateRefundTx(createTestTxBytes(t, 4001)).
		Save(ctx)
	require.NoError(t, err)

	// Call through the public gRPC handler entry point.
	handler := NewInternalTransferHandler(cfg)
	err = handler.SettleSenderKeyTweak(ctx, &pbinternal.SettleSenderKeyTweakRequest{
		TransferId: transfer.ID.String(),
		Action:     pbinternal.SettleKeyTweakAction_COMMIT,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "transfer leaf has no key tweak stored")
	assert.Contains(t, err.Error(), leaf.ID.String())
}

func TestCommitSenderKeyTweaks_RejectsNilProofValue(t *testing.T) {
	ctx, dbCtx := db.ConnectToTestPostgres(t)
	cfg := sparktesting.TestConfig(t)
	rng := rand.NewChaCha8([32]byte{122})

	senderPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	receiverPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	keysharePrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	publicSharePrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	client := dbCtx.Client

	signingKeyshare, err := client.SigningKeyshare.Create().
		SetStatus(st.KeyshareStatusAvailable).
		SetSecretShare(keysharePrivKey).
		SetPublicShares(map[string]keys.Public{cfg.Identifier: publicSharePrivKey.Public()}).
		SetPublicKey(keysharePrivKey.Public()).
		SetMinSigners(2).
		SetCoordinatorIndex(0).
		Save(ctx)
	require.NoError(t, err)

	tree, err := client.Tree.Create().
		SetStatus(st.TreeStatusAvailable).
		SetNetwork(btcnetwork.Regtest).
		SetOwnerIdentityPubkey(senderPrivKey.Public()).
		SetBaseTxid(st.NewRandomTxIDForTesting(t)).
		SetVout(0).
		Save(ctx)
	require.NoError(t, err)

	leaf, err := client.TreeNode.Create().
		SetStatus(st.TreeNodeStatusAvailable).
		SetTree(tree).
		SetNetwork(tree.Network).
		SetSigningKeyshare(signingKeyshare).
		SetValue(1000).
		SetVerifyingPubkey(keys.MustGeneratePrivateKeyFromRand(rng).Public()).
		SetOwnerIdentityPubkey(senderPrivKey.Public()).
		SetOwnerSigningPubkey(keys.MustGeneratePrivateKeyFromRand(rng).Public()).
		SetRawTx(createTestTxBytes(t, 5300)).
		SetRawRefundTx(createTestTxBytes(t, 5301)).
		SetVout(0).
		Save(ctx)
	require.NoError(t, err)

	transfer, err := client.Transfer.Create().
		SetNetwork(btcnetwork.Regtest).
		SetStatus(st.TransferStatusSenderKeyTweakPending).
		SetType(st.TransferTypeTransfer).
		SetSenderIdentityPubkey(senderPrivKey.Public()).
		SetReceiverIdentityPubkey(receiverPrivKey.Public()).
		SetTotalValue(1000).
		SetExpiryTime(time.Now().Add(24 * time.Hour)).
		Save(ctx)
	require.NoError(t, err)

	secretShare, pubkeySharesTweak := createValidSecretShares(cfg, rng)
	keyTweakBytes, err := proto.Marshal(&sparkProto.SendLeafKeyTweak{
		LeafId:            leaf.ID.String(),
		SecretShareTweak:  secretShare,
		PubkeySharesTweak: pubkeySharesTweak,
		SecretCipher:      []byte("encrypted-secret-share"),
		Signature:         []byte("mock-key-tweak-signature"),
	})
	require.NoError(t, err)
	_, err = client.TransferLeaf.Create().
		SetTransfer(transfer).
		SetLeaf(leaf).
		SetPreviousRefundTx(createTestTxBytes(t, 5302)).
		SetIntermediateRefundTx(createTestTxBytes(t, 5303)).
		SetKeyTweak(keyTweakBytes).
		Save(ctx)
	require.NoError(t, err)

	var commitErr error
	baseHandler := NewBaseTransferHandler(cfg)
	require.NotPanics(t, func() {
		_, commitErr = baseHandler.CommitSenderKeyTweaks(ctx, transfer.ID, map[string]*sparkProto.SecretProof{
			leaf.ID.String(): nil,
		})
	})
	require.ErrorContains(t, commitErr, "key tweak proof value is nil")
}

func TestValidateKeyTweakProofRejectsNilProofValue(t *testing.T) {
	ctx, dbCtx := db.ConnectToTestPostgres(t)
	cfg := sparktesting.TestConfig(t)
	rng := rand.NewChaCha8([32]byte{123})
	client := dbCtx.Client

	senderPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	receiverPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	keysharePrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	publicSharePrivKey := keys.MustGeneratePrivateKeyFromRand(rng)

	signingKeyshare, err := client.SigningKeyshare.Create().
		SetStatus(st.KeyshareStatusAvailable).
		SetSecretShare(keysharePrivKey).
		SetPublicShares(map[string]keys.Public{cfg.Identifier: publicSharePrivKey.Public()}).
		SetPublicKey(keysharePrivKey.Public()).
		SetMinSigners(2).
		SetCoordinatorIndex(0).
		Save(ctx)
	require.NoError(t, err)

	tree, err := client.Tree.Create().
		SetStatus(st.TreeStatusAvailable).
		SetNetwork(btcnetwork.Regtest).
		SetOwnerIdentityPubkey(senderPrivKey.Public()).
		SetBaseTxid(st.NewRandomTxIDForTesting(t)).
		SetVout(0).
		Save(ctx)
	require.NoError(t, err)

	leaf, err := client.TreeNode.Create().
		SetStatus(st.TreeNodeStatusAvailable).
		SetTree(tree).
		SetNetwork(tree.Network).
		SetSigningKeyshare(signingKeyshare).
		SetValue(1000).
		SetVerifyingPubkey(keys.MustGeneratePrivateKeyFromRand(rng).Public()).
		SetOwnerIdentityPubkey(senderPrivKey.Public()).
		SetOwnerSigningPubkey(keys.MustGeneratePrivateKeyFromRand(rng).Public()).
		SetRawTx(createTestTxBytes(t, 5400)).
		SetRawRefundTx(createTestTxBytes(t, 5401)).
		SetVout(0).
		Save(ctx)
	require.NoError(t, err)

	transfer, err := client.Transfer.Create().
		SetNetwork(btcnetwork.Regtest).
		SetStatus(st.TransferStatusReceiverKeyTweaked).
		SetType(st.TransferTypeTransfer).
		SetSenderIdentityPubkey(senderPrivKey.Public()).
		SetReceiverIdentityPubkey(receiverPrivKey.Public()).
		SetTotalValue(1000).
		SetExpiryTime(time.Now().Add(24 * time.Hour)).
		Save(ctx)
	require.NoError(t, err)

	secretShare, _ := createValidSecretShares(cfg, rng)
	keyTweakBytes, err := proto.Marshal(&sparkProto.ClaimLeafKeyTweak{
		LeafId:           leaf.ID.String(),
		SecretShareTweak: secretShare,
	})
	require.NoError(t, err)
	transferLeaf, err := client.TransferLeaf.Create().
		SetTransfer(transfer).
		SetLeaf(leaf).
		SetPreviousRefundTx(createTestTxBytes(t, 5402)).
		SetIntermediateRefundTx(createTestTxBytes(t, 5403)).
		SetKeyTweak(keyTweakBytes).
		Save(ctx)
	require.NoError(t, err)

	loadedTransferLeaf, err := client.TransferLeaf.Query().
		Where(enttransferleaf.ID(transferLeaf.ID)).
		WithLeaf().
		Only(ctx)
	require.NoError(t, err)

	var validateErr error
	require.NotPanics(t, func() {
		validateErr = NewTransferHandler(cfg).ValidateKeyTweakProof(ctx, []*ent.TransferLeaf{loadedTransferLeaf}, map[string]*sparkProto.SecretProof{
			leaf.ID.String(): nil,
		})
	})
	require.ErrorContains(t, validateErr, "key tweak proof value is nil")
}

func TestDeliverSenderKeyTweak_MissingKeyTweakForLeaf(t *testing.T) {
	ctx, dbCtx := db.ConnectToTestPostgres(t)
	rng := rand.NewChaCha8([32]byte{99})

	cfg := sparktesting.TestConfig(t)

	senderIdentityPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	receiverIdentityPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	ownerIdentityPrivKey := senderIdentityPrivKey

	// Create two signing keyshares, trees, and leaves.
	var leaves [2]*ent.TreeNode
	for i := range leaves {
		keysharePrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
		publicSharePrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
		signingKeyshare, err := dbCtx.Client.SigningKeyshare.Create().
			SetStatus(st.KeyshareStatusAvailable).
			SetSecretShare(keysharePrivKey).
			SetPublicShares(map[string]keys.Public{"test": publicSharePrivKey.Public()}).
			SetPublicKey(keysharePrivKey.Public()).
			SetMinSigners(2).
			SetCoordinatorIndex(0).
			Save(ctx)
		require.NoError(t, err)

		baseTxid := st.NewRandomTxIDForTesting(t)
		tree, err := dbCtx.Client.Tree.Create().
			SetStatus(st.TreeStatusAvailable).
			SetNetwork(btcnetwork.Regtest).
			SetOwnerIdentityPubkey(ownerIdentityPrivKey.Public()).
			SetBaseTxid(baseTxid).
			SetVout(0).
			Save(ctx)
		require.NoError(t, err)

		verifyingPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
		ownerSigningPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
		leaf, err := dbCtx.Client.TreeNode.Create().
			SetStatus(st.TreeNodeStatusAvailable).
			SetTree(tree).
			SetNetwork(tree.Network).
			SetSigningKeyshare(signingKeyshare).
			SetValue(1000).
			SetVerifyingPubkey(verifyingPrivKey.Public()).
			SetOwnerIdentityPubkey(ownerIdentityPrivKey.Public()).
			SetOwnerSigningPubkey(ownerSigningPrivKey.Public()).
			SetRawTx(createTestTxBytes(t, int64(3000+i))).
			SetRawRefundTx(createTestTxBytes(t, int64(3100+i))).
			SetVout(0).
			Save(ctx)
		require.NoError(t, err)
		leaves[i] = leaf
	}

	// Create a transfer in SenderInitiated with both leaves.
	transferID := uuid.New()
	transfer, err := dbCtx.Client.Transfer.Create().
		SetID(transferID).
		SetNetwork(btcnetwork.Regtest).
		SetStatus(st.TransferStatusSenderInitiated).
		SetType(st.TransferTypeTransfer).
		SetSenderIdentityPubkey(senderIdentityPrivKey.Public()).
		SetReceiverIdentityPubkey(receiverIdentityPrivKey.Public()).
		SetTotalValue(2000).
		SetExpiryTime(time.Now().Add(24 * time.Hour)).
		Save(ctx)
	require.NoError(t, err)

	for _, leaf := range leaves {
		_, err = dbCtx.Client.TransferLeaf.Create().
			SetTransfer(transfer).
			SetLeaf(leaf).
			SetPreviousRefundTx(createTestTxBytes(t, 4000)).
			SetIntermediateRefundTx(createTestTxBytes(t, 4001)).
			Save(ctx)
		require.NoError(t, err)
	}

	// Build a transfer package with key tweaks for ONLY the first leaf (not the second).
	// Uses buildKeyTweakPackageForLeaves + signTransferPackage so the signature covers
	// the actual LeavesToSend payload (not an empty slice).
	keyTweakPackage := buildKeyTweakPackageForLeaves(t, cfg, rng, []uuid.UUID{leaves[0].ID})
	pkg := &sparkProto.TransferPackage{
		LeavesToSend: []*sparkProto.UserSignedTxSigningJob{
			{LeafId: leaves[0].ID.String(), RawTx: leaves[0].RawRefundTx},
			{LeafId: leaves[1].ID.String(), RawTx: leaves[1].RawRefundTx},
		},
		KeyTweakPackage: keyTweakPackage,
	}
	signTransferPackage(t, pkg, transferID, ownerIdentityPrivKey)

	req := &pbinternal.DeliverSenderKeyTweakRequest{
		TransferId:              transferID.String(),
		SenderIdentityPublicKey: senderIdentityPrivKey.Public().Serialize(),
		TransferPackage:         pkg,
	}

	handler := NewInternalTransferHandler(cfg)
	err = handler.DeliverSenderKeyTweak(ctx, req)

	// Should fail because leaf[1] has no key tweak in the encrypted package.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key tweak count mismatch")

	// Verify transfer status was NOT updated to SenderKeyTweakPending.
	updatedTransfer, err := dbCtx.Client.Transfer.Get(ctx, transferID)
	require.NoError(t, err)
	assert.Equal(t, st.TransferStatusSenderInitiated, updatedTransfer.Status,
		"transfer must remain SenderInitiated when DeliverSenderKeyTweak fails")
}
