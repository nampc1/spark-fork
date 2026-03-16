//go:build lightspark

package handler

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/lightsparkdev/spark/common/keys"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	enttreenode "github.com/lightsparkdev/spark/so/ent/treenode"

	entsql "entgo.io/ent/dialect/sql"
)

const maxChainDepth = 100

type FixLeafKeyshareSplitHandler struct {
	config *so.Config
}

func NewFixLeafKeyshareSplitHandler(config *so.Config) *FixLeafKeyshareSplitHandler {
	return &FixLeafKeyshareSplitHandler{config: config}
}

func (h *FixLeafKeyshareSplitHandler) FixLeafKeyshareSplit(
	ctx context.Context,
	req *pbssp.FixLeafKeyshareSplitRequest,
) (*pbssp.FixLeafKeyshareSplitResponse, error) {
	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get db from context: %w", err)
	}

	parentNodeID, err := uuid.Parse(req.ParentNodeId)
	if err != nil {
		return nil, fmt.Errorf("invalid parent node id: %w", err)
	}

	parentNode, err := db.TreeNode.Query().
		Where(enttreenode.ID(parentNodeID)).
		WithSigningKeyshare().
		WithChildren(func(q *ent.TreeNodeQuery) {
			q.Order(enttreenode.ByCreateTime())
		}).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query parent node: %w", err)
	}

	sparkOperatorKeyshare := parentNode.Edges.SigningKeyshare
	if sparkOperatorKeyshare == nil {
		return nil, fmt.Errorf("parent node has no signing keyshare")
	}

	children := parentNode.Edges.Children
	if len(children) != 2 {
		return nil, fmt.Errorf("parent node must have exactly 2 children, got %d", len(children))
	}

	userSigningPubkey, err := keys.ParsePublicKey(req.ParentNodeSigningPubkey)
	if err != nil {
		return nil, fmt.Errorf("invalid parent node signing pubkey: %w", err)
	}

	leftChildUserSigningPubkey, err := keys.ParsePublicKey(req.LeftChildSigningPubkey)
	if err != nil {
		return nil, fmt.Errorf("invalid left child signing pubkey: %w", err)
	}

	rightChildUserSigningPubkey, err := keys.ParsePublicKey(req.RightChildSigningPubkey)
	if err != nil {
		return nil, fmt.Errorf("invalid right child signing pubkey: %w", err)
	}

	expectedVerifyingKey := sparkOperatorKeyshare.PublicKey.Add(userSigningPubkey)
	if !expectedVerifyingKey.Equals(parentNode.VerifyingPubkey) {
		return nil, fmt.Errorf("parent verifying key mismatch: SO pubkey + user signing pubkey != verifying pubkey")
	}

	childSum := leftChildUserSigningPubkey.Add(rightChildUserSigningPubkey)
	if !childSum.Equals(userSigningPubkey) {
		return nil, fmt.Errorf("child signing pubkeys do not sum to parent signing pubkey")
	}

	leftChain, err := walkChain(ctx, db, children[0].ID)
	if err != nil {
		return nil, fmt.Errorf("failed to walk left chain: %w", err)
	}

	rightChain, err := walkChain(ctx, db, children[1].ID)
	if err != nil {
		return nil, fmt.Errorf("failed to walk right chain: %w", err)
	}

	// Acquire left SO keyshare
	var leftSparkOperatorKeyshare *ent.SigningKeyshare
	if len(req.LeftSigningKeyshareId) > 0 {
		leftKeyshareID, err := uuid.Parse(req.LeftSigningKeyshareId)
		if err != nil {
			return nil, fmt.Errorf("invalid left signing keyshare id: %w", err)
		}
		leftSparkOperatorKeyshare, err = db.SigningKeyshare.Get(ctx, leftKeyshareID)
		if err != nil {
			return nil, fmt.Errorf("failed to get left keyshare: %w", err)
		}
		if leftSparkOperatorKeyshare.CoordinatorIndex != h.config.Index {
			return nil, fmt.Errorf("left keyshare coordinator index %d does not match this operator's index %d",
				leftSparkOperatorKeyshare.CoordinatorIndex, h.config.Index)
		}
	} else {
		leftSparkOperatorKeyshare, err = grabOneUnusedKeyshare(ctx, db, h.config)
		if err != nil {
			return nil, fmt.Errorf("failed to get unused keyshare: %w", err)
		}
	}

	// Derive right SO keyshare: parent_keyshare = left_keyshare + right_keyshare
	var rightKeyshareID uuid.UUID
	if len(req.RightSigningKeyshareId) > 0 {
		rightKeyshareID, err = uuid.Parse(req.RightSigningKeyshareId)
		if err != nil {
			return nil, fmt.Errorf("invalid right signing keyshare id: %w", err)
		}
	} else {
		rightKeyshareID, err = uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("failed to generate uuid: %w", err)
		}
	}

	rightSparkOperatorKeyshare, err := ent.CalculateAndStoreLastKey(
		ctx, h.config, sparkOperatorKeyshare, []*ent.SigningKeyshare{leftSparkOperatorKeyshare}, rightKeyshareID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate right keyshare: %w", err)
	}

	// Update left chain
	leftVerifyingKey := leftSparkOperatorKeyshare.PublicKey.Add(leftChildUserSigningPubkey)
	if err := updateChainWithRawSQL(ctx, db, leftChain, leftSparkOperatorKeyshare.ID, leftChildUserSigningPubkey, leftVerifyingKey); err != nil {
		return nil, fmt.Errorf("failed to update left chain: %w", err)
	}

	// Update right chain
	rightVerifyingKey := rightSparkOperatorKeyshare.PublicKey.Add(rightChildUserSigningPubkey)
	if err := updateChainWithRawSQL(ctx, db, rightChain, rightSparkOperatorKeyshare.ID, rightChildUserSigningPubkey, rightVerifyingKey); err != nil {
		return nil, fmt.Errorf("failed to update right chain: %w", err)
	}

	return &pbssp.FixLeafKeyshareSplitResponse{
		LeftSigningKeyshareId:  leftSparkOperatorKeyshare.ID.String(),
		RightSigningKeyshareId: rightSparkOperatorKeyshare.ID.String(),
	}, nil
}

// grabOneUnusedKeyshare selects one available keyshare and marks it IN_USE
// within the current transaction (does not commit).
func grabOneUnusedKeyshare(ctx context.Context, db *ent.Client, config *so.Config) (*ent.SigningKeyshare, error) {
	var keyshares []*ent.SigningKeyshare

	//nolint:forbidigo // Raw SQL to select+update in one step within the current transaction
	rows, err := db.QueryContext(ctx, `
		WITH selected_ids AS (
			SELECT id FROM signing_keyshares
			WHERE status = 'AVAILABLE' AND coordinator_index = $1
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE signing_keyshares
		SET status = 'IN_USE', update_time = NOW()
		FROM selected_ids
		WHERE signing_keyshares.id = selected_ids.id
		RETURNING signing_keyshares.*
	`, []any{config.Index}...)
	if err != nil {
		return nil, err
	}
	ent.MarkTxDirty(ctx)
	defer func() { _ = rows.Close() }()

	if err := entsql.ScanSlice(rows, &keyshares); err != nil {
		return nil, err
	}

	if len(keyshares) == 0 {
		return nil, fmt.Errorf("no available signing keyshares")
	}

	return keyshares[0], nil
}

// walkChain walks a chain of single-child nodes starting from startID using
// a recursive CTE. Returns all node IDs in depth order. Returns an error if
// any node has more than 1 child or the chain exceeds maxChainDepth.
func walkChain(ctx context.Context, db *ent.Client, startID uuid.UUID) ([]uuid.UUID, error) {
	type chainRow struct {
		ID       uuid.UUID `json:"id"`
		Depth    int       `json:"depth"`
		Children int       `json:"children"`
	}
	var rows []chainRow

	//nolint:forbidigo // Recursive CTE to walk the chain in a single query
	sqlRows, err := db.QueryContext(ctx, `
		WITH RECURSIVE chain AS (
			SELECT id, 1 AS depth FROM tree_nodes WHERE id = $1
			UNION ALL
			SELECT tn.id, c.depth + 1
			FROM tree_nodes tn
			JOIN chain c ON tn.tree_node_parent = c.id
			WHERE c.depth < $2
		)
		SELECT c.id, c.depth,
			(SELECT COUNT(*) FROM tree_nodes tn2 WHERE tn2.tree_node_parent = c.id) AS children
		FROM chain c
		ORDER BY c.depth
	`, startID, maxChainDepth)
	if err != nil {
		return nil, fmt.Errorf("failed to walk chain from node %s: %w", startID, err)
	}
	defer func() { _ = sqlRows.Close() }()

	for sqlRows.Next() {
		var r chainRow
		if err := sqlRows.Scan(&r.ID, &r.Depth, &r.Children); err != nil {
			return nil, fmt.Errorf("failed to scan chain row: %w", err)
		}
		rows = append(rows, r)
	}
	if err := sqlRows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate chain rows: %w", err)
	}

	if len(rows) == 0 {
		return nil, fmt.Errorf("node %s not found", startID)
	}

	chain := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		if r.Children > 1 {
			return nil, fmt.Errorf("node %s has %d children, expected 0 or 1", r.ID, r.Children)
		}
		chain = append(chain, r.ID)
	}

	if len(chain) >= maxChainDepth {
		return nil, fmt.Errorf("chain starting at %s exceeds maximum depth %d", startID, maxChainDepth)
	}

	return chain, nil
}

// updateChainWithRawSQL updates all nodes in a chain using raw SQL to bypass
// Ent's immutability constraint on verifying_pubkey.
func updateChainWithRawSQL(
	ctx context.Context,
	db *ent.Client,
	nodeIDs []uuid.UUID,
	keyshareID uuid.UUID,
	ownerSigningPubkey keys.Public,
	verifyingPubkey keys.Public,
) error {
	//nolint:forbidigo // Raw SQL needed to update immutable verifying_pubkey field
	_, err := db.ExecContext(ctx, `
		UPDATE tree_nodes
		SET tree_node_signing_keyshare = $1,
			owner_signing_pubkey = $2,
			verifying_pubkey = $3,
			update_time = NOW()
		WHERE id = ANY($4)
	`, keyshareID, ownerSigningPubkey.Serialize(), verifyingPubkey.Serialize(), pq.Array(nodeIDs))
	if err != nil {
		return fmt.Errorf("failed to update chain nodes: %w", err)
	}
	ent.MarkTxDirty(ctx)
	return nil
}
