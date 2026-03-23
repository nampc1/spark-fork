//go:build lightspark

package handler

import (
	"math/rand/v2"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	eciesgo "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/keys"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	sparktesting "github.com/lightsparkdev/spark/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// buildKeyTweakPackageForLeaves encrypts key tweaks for the given leaf IDs into
// a TransferPackage.KeyTweakPackage map. Only the leaf IDs listed in tweakedLeafIDs
// will have entries in the encrypted payload.
func buildKeyTweakPackageForLeaves(
	t *testing.T,
	cfg *so.Config,
	rng *rand.ChaCha8,
	tweakedLeafIDs []uuid.UUID,
) map[string][]byte {
	t.Helper()

	var leafTweaks []*pb.SendLeafKeyTweak
	for _, leafID := range tweakedLeafIDs {
		secretShare, pubkeySharesTweak := createValidSecretShares(cfg, rng)
		publicKey, err := eciesgo.NewPublicKeyFromBytes(cfg.IdentityPublicKey().Serialize())
		require.NoError(t, err)
		secretCipher, err := eciesgo.Encrypt(publicKey, secretShare.GetSecretShare())
		require.NoError(t, err)

		leafTweaks = append(leafTweaks, &pb.SendLeafKeyTweak{
			LeafId:            leafID.String(),
			SecretShareTweak:  secretShare,
			PubkeySharesTweak: pubkeySharesTweak,
			SecretCipher:      secretCipher,
			Signature:         []byte("mock_signature_for_testing"),
		})
	}

	publicKey, err := eciesgo.NewPublicKeyFromBytes(cfg.IdentityPublicKey().Serialize())
	require.NoError(t, err)

	leafTweaksProto := &pb.SendLeafKeyTweaks{LeavesToSend: leafTweaks}
	data, err := proto.Marshal(leafTweaksProto)
	require.NoError(t, err)
	encrypted, err := eciesgo.Encrypt(publicKey, data)
	require.NoError(t, err)

	return map[string][]byte{cfg.Identifier: encrypted}
}

// signTransferPackage signs the given TransferPackage and sets UserSignature.
func signTransferPackage(
	t *testing.T,
	pkg *pb.TransferPackage,
	transferID uuid.UUID,
	senderPrivKey keys.Private,
) {
	t.Helper()
	payload := common.GetTransferPackageSigningPayload(transferID, pkg)
	sig := ecdsa.Sign(senderPrivKey.ToBTCEC(), payload)
	pkg.UserSignature = sig.Serialize()
}

// TestValidateTransferPackage_MissingKeyTweakForRefundLeaf verifies that
// ValidateTransferPackage rejects a package where a refund-transaction leaf
// has no corresponding entry in the encrypted key tweak payload.
func TestValidateTransferPackage_MissingKeyTweakForRefundLeaf(t *testing.T) {
	cfg := sparktesting.TestConfig(t)
	rng := rand.NewChaCha8([32]byte{42})

	senderPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	transferID := uuid.New()

	leafWithTweak := uuid.New()
	leafWithoutTweak := uuid.New()

	// Encrypt key tweaks for ONLY leafWithTweak — leafWithoutTweak is missing.
	keyTweakPackage := buildKeyTweakPackageForLeaves(t, cfg, rng, []uuid.UUID{leafWithTweak})

	pkg := &pb.TransferPackage{
		LeavesToSend: []*pb.UserSignedTxSigningJob{
			{LeafId: leafWithTweak.String(), RawTx: createTestTxBytes(t, 1000)},
			{LeafId: leafWithoutTweak.String(), RawTx: createTestTxBytes(t, 2000)},
		},
		KeyTweakPackage: keyTweakPackage,
	}
	signTransferPackage(t, pkg, transferID, senderPrivKey)

	h := NewBaseTransferHandler(cfg)
	_, err := h.ValidateTransferPackage(
		t.Context(),
		transferID,
		pkg,
		senderPrivKey.Public(),
		false,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "key tweak count mismatch")
}

// TestValidateTransferPackage_AllLeavesHaveKeyTweaks verifies that
// ValidateTransferPackage succeeds when every refund-transaction leaf
// has a matching key tweak entry.
func TestValidateTransferPackage_AllLeavesHaveKeyTweaks(t *testing.T) {
	cfg := sparktesting.TestConfig(t)
	rng := rand.NewChaCha8([32]byte{43})

	senderPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	transferID := uuid.New()

	leaf1 := uuid.New()
	leaf2 := uuid.New()

	// Encrypt key tweaks for BOTH leaves.
	keyTweakPackage := buildKeyTweakPackageForLeaves(t, cfg, rng, []uuid.UUID{leaf1, leaf2})

	pkg := &pb.TransferPackage{
		LeavesToSend: []*pb.UserSignedTxSigningJob{
			{LeafId: leaf1.String(), RawTx: createTestTxBytes(t, 1000)},
			{LeafId: leaf2.String(), RawTx: createTestTxBytes(t, 2000)},
		},
		KeyTweakPackage: keyTweakPackage,
	}
	signTransferPackage(t, pkg, transferID, senderPrivKey)

	h := NewBaseTransferHandler(cfg)
	tweaksMap, err := h.ValidateTransferPackage(
		t.Context(),
		transferID,
		pkg,
		senderPrivKey.Public(),
		false,
	)

	require.NoError(t, err)
	assert.Len(t, tweaksMap, 2)
	assert.Contains(t, tweaksMap, leaf1.String())
	assert.Contains(t, tweaksMap, leaf2.String())
}

// TestValidateTransferPackage_MismatchedKeyTweakLeafID verifies that
// ValidateTransferPackage rejects a package where the key tweak count matches
// the refund transaction count but one tweak is for a leaf ID not in the
// refund transactions (covers the per-leaf ID check after the count check).
func TestValidateTransferPackage_MismatchedKeyTweakLeafID(t *testing.T) {
	cfg := sparktesting.TestConfig(t)
	rng := rand.NewChaCha8([32]byte{46})

	senderPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	transferID := uuid.New()

	leaf1 := uuid.New()
	leaf2 := uuid.New()
	wrongLeaf := uuid.New()

	// Encrypt key tweaks for leaf1 and wrongLeaf (not leaf2).
	// Count matches (2 vs 2) but leaf2 has no tweak.
	keyTweakPackage := buildKeyTweakPackageForLeaves(t, cfg, rng, []uuid.UUID{leaf1, wrongLeaf})

	pkg := &pb.TransferPackage{
		LeavesToSend: []*pb.UserSignedTxSigningJob{
			{LeafId: leaf1.String(), RawTx: createTestTxBytes(t, 1000)},
			{LeafId: leaf2.String(), RawTx: createTestTxBytes(t, 2000)},
		},
		KeyTweakPackage: keyTweakPackage,
	}
	signTransferPackage(t, pkg, transferID, senderPrivKey)

	h := NewBaseTransferHandler(cfg)
	_, err := h.ValidateTransferPackage(
		t.Context(),
		transferID,
		pkg,
		senderPrivKey.Public(),
		false,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "key tweak missing for leaf")
	assert.Contains(t, err.Error(), leaf2.String())
}

// TestValidateTransferPackage_ExtraKeyTweakForUnknownLeaf verifies that
// ValidateTransferPackage rejects a package where the encrypted key tweak
// payload contains entries for leaf IDs not present in the refund transactions.
func TestValidateTransferPackage_ExtraKeyTweakForUnknownLeaf(t *testing.T) {
	cfg := sparktesting.TestConfig(t)
	rng := rand.NewChaCha8([32]byte{45})

	senderPrivKey := keys.MustGeneratePrivateKeyFromRand(rng)
	transferID := uuid.New()

	realLeaf := uuid.New()
	extraLeaf := uuid.New()

	// Encrypt key tweaks for both realLeaf AND extraLeaf, but only include
	// realLeaf in LeavesToSend. The extra entry should be rejected.
	keyTweakPackage := buildKeyTweakPackageForLeaves(t, cfg, rng, []uuid.UUID{realLeaf, extraLeaf})

	pkg := &pb.TransferPackage{
		LeavesToSend: []*pb.UserSignedTxSigningJob{
			{LeafId: realLeaf.String(), RawTx: createTestTxBytes(t, 1000)},
		},
		KeyTweakPackage: keyTweakPackage,
	}
	signTransferPackage(t, pkg, transferID, senderPrivKey)

	h := NewBaseTransferHandler(cfg)
	_, err := h.ValidateTransferPackage(
		t.Context(),
		transferID,
		pkg,
		senderPrivKey.Public(),
		false,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "key tweak count mismatch")
}
