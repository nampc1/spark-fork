//go:build lightspark

package handler

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/google/uuid"

	"github.com/lightsparkdev/spark"
	"github.com/lightsparkdev/spark/common"
	pbfrost "github.com/lightsparkdev/spark/proto/frost"
	pbgossip "github.com/lightsparkdev/spark/proto/gossip"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	enttreenode "github.com/lightsparkdev/spark/so/ent/treenode"
	"github.com/lightsparkdev/spark/so/helper"
)

// ReSignSubtreeHandler re-signs all Bitcoin transactions in a subtree
// after fix_leaf_keyshare_split changed the verifying keys.
type ReSignSubtreeHandler struct {
	config *so.Config
}

func NewReSignSubtreeHandler(config *so.Config) *ReSignSubtreeHandler {
	return &ReSignSubtreeHandler{config: config}
}

// subtreeNode holds a loaded tree node with its role in the subtree.
type subtreeNode struct {
	node     *ent.TreeNode
	isLeaf   bool
	isParent bool
}

func (h *ReSignSubtreeHandler) ReSignSubtree(
	ctx context.Context,
	req *pbssp.ReSignSubtreeRequest,
) (*pbssp.ReSignSubtreeResponse, error) {
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
		ForUpdate().
		WithSigningKeyshare().
		WithParent(func(q *ent.TreeNodeQuery) {
			q.WithSigningKeyshare()
		}).
		WithChildren(func(q *ent.TreeNodeQuery) {
			q.Order(enttreenode.ByID()).WithSigningKeyshare()
		}).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query parent node: %w", err)
	}

	children := parentNode.Edges.Children
	if len(children) != 2 {
		return nil, fmt.Errorf("parent node must have exactly 2 children, got %d", len(children))
	}

	leftChainIDs, err := walkChain(ctx, db, children[0].ID)
	if err != nil {
		return nil, fmt.Errorf("failed to walk left chain: %w", err)
	}
	rightChainIDs, err := walkChain(ctx, db, children[1].ID)
	if err != nil {
		return nil, fmt.Errorf("failed to walk right chain: %w", err)
	}

	allChainIDs := append(leftChainIDs, rightChainIDs...)
	chainNodes, err := db.TreeNode.Query().
		Where(enttreenode.IDIn(allChainIDs...)).
		ForUpdate().
		WithSigningKeyshare().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load chain nodes: %w", err)
	}
	chainNodeMap := make(map[uuid.UUID]*ent.TreeNode, len(chainNodes))
	for _, n := range chainNodes {
		chainNodeMap[n.ID] = n
	}

	subtreeNodes := h.buildSubtreeNodes(parentNode, leftChainIDs, rightChainIDs, chainNodeMap)

	parentParent := parentNode.Edges.Parent
	if parentParent == nil {
		return nil, fmt.Errorf("parent node has no parent node")
	}
	parentParentTx, err := common.TxFromRawTxBytes(parentParent.RawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse parent's parent node_tx: %w", err)
	}

	// Process each node: validate client tx, build signing jobs
	var allSigningJobs []*helper.SigningJobWithPregeneratedNonce
	type jobMapping struct {
		nodeID  string
		txIndex int
	}
	var jobMappings []jobMapping

	constructedNodeTxs := make(map[uuid.UUID]*wire.MsgTx)

	for _, sn := range subtreeNodes {
		nodeIDStr := sn.node.ID.String()
		nodeJobs, ok := req.NodeSigningJobs[nodeIDStr]
		if !ok {
			return nil, fmt.Errorf("missing signing jobs for node %s", nodeIDStr)
		}

		keyshare := sn.node.Edges.SigningKeyshare
		if keyshare == nil {
			return nil, fmt.Errorf("node %s has no signing keyshare", nodeIDStr)
		}

		// Parse all raw txs upfront
		var nodeTxs []*wire.MsgTx
		for j, job := range nodeJobs.SigningJobs {
			tx, parseErr := common.TxFromRawTxBytes(job.RawTx)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse tx %d for node %s: %w", j, nodeIDStr, parseErr)
			}
			nodeTxs = append(nodeTxs, tx)
		}
		if len(nodeTxs) > 0 {
			constructedNodeTxs[sn.node.ID] = nodeTxs[0]
		}

		var prevOutput *wire.TxOut
		var jobs []*helper.SigningJobWithPregeneratedNonce

		if sn.isParent {
			if int(parentNode.Vout) >= len(parentParentTx.TxOut) {
				return nil, fmt.Errorf("parent node Vout %d out of range for parent tx with %d outputs", parentNode.Vout, len(parentParentTx.TxOut))
			}
			prevOutput = parentParentTx.TxOut[parentNode.Vout]
			jobs, err = h.buildSplitTxSigningJobs(sn.node, keyshare, prevOutput, children, nodeJobs)
		} else if sn.isLeaf {
			prevOutput, err = h.getPrevOutputForChainNode(sn.node, parentNode, constructedNodeTxs, leftChainIDs, rightChainIDs, children)
			if err != nil {
				return nil, fmt.Errorf("failed to get prevOutput for leaf %s: %w", nodeIDStr, err)
			}
			jobs, err = h.buildLeafSigningJobs(sn.node, keyshare, prevOutput, nodeJobs)
		} else {
			prevOutput, err = h.getPrevOutputForChainNode(sn.node, parentNode, constructedNodeTxs, leftChainIDs, rightChainIDs, children)
			if err != nil {
				return nil, fmt.Errorf("failed to get prevOutput for node %s: %w", nodeIDStr, err)
			}
			jobs, err = h.buildIntermediateSigningJobs(sn.node, keyshare, prevOutput, nodeJobs)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to build signing jobs for node %s: %w", nodeIDStr, err)
		}

		for i, job := range jobs {
			allSigningJobs = append(allSigningJobs, job)
			jobMappings = append(jobMappings, jobMapping{nodeID: nodeIDStr, txIndex: i})
		}
	}

	// Sign all jobs via FROST
	signingResults, err := helper.SignFrostWithPregeneratedNonce(ctx, h.config, allSigningJobs)
	if err != nil {
		return nil, fmt.Errorf("failed to sign subtree transactions: %w", err)
	}

	// Aggregate signatures and apply to transactions
	frostConn, err := h.config.NewFrostGRPCConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to frost signer: %w", err)
	}
	defer frostConn.Close()
	frostClient := pbfrost.NewFrostServiceClient(frostConn)

	responseMap := make(map[string]*pbssp.NodeSignatures)
	signedTxBytesMap := make(map[string][][]byte)

	for i, result := range signingResults {
		mapping := jobMappings[i]
		nodeIDStr := mapping.nodeID
		userSigningJob := req.NodeSigningJobs[nodeIDStr].SigningJobs[mapping.txIndex]

		nodeUUID, _ := uuid.Parse(nodeIDStr)
		var node *ent.TreeNode
		if parentNode.ID == nodeUUID {
			node = parentNode
		} else {
			node = chainNodeMap[nodeUUID]
		}

		if userSigningJob.SigningCommitments == nil {
			return nil, fmt.Errorf("nil signing_commitments for node %s tx %d", nodeIDStr, mapping.txIndex)
		}

		aggregateResp, err := frostClient.AggregateFrost(ctx, &pbfrost.AggregateFrostRequest{
			Message:            result.Message,
			SignatureShares:    result.SignatureShares,
			PublicShares:       result.PublicKeys,
			VerifyingKey:       node.VerifyingPubkey.Serialize(),
			Commitments:        userSigningJob.SigningCommitments.SigningCommitments,
			UserCommitments:    userSigningJob.SigningNonceCommitment,
			UserPublicKey:      node.OwnerSigningPubkey.Serialize(),
			UserSignatureShare: userSigningJob.UserSignature,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to aggregate signature for node %s tx %d: %w", nodeIDStr, mapping.txIndex, err)
		}

		rawTx, err := common.TxFromRawTxBytes(userSigningJob.RawTx)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tx for node %s: %w", nodeIDStr, err)
		}
		txBytes, err := common.SerializeTx(rawTx)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize tx: %w", err)
		}
		txBytes, err = common.UpdateTxWithSignature(txBytes, 0, aggregateResp.Signature)
		if err != nil {
			return nil, fmt.Errorf("failed to apply signature: %w", err)
		}

		signedTxBytesMap[nodeIDStr] = append(signedTxBytesMap[nodeIDStr], txBytes)

		if _, ok := responseMap[nodeIDStr]; !ok {
			responseMap[nodeIDStr] = &pbssp.NodeSignatures{}
		}
		responseMap[nodeIDStr].Signatures = append(responseMap[nodeIDStr].Signatures, aggregateResp.Signature)
	}

	if err := h.updateDBWithSignedTxs(ctx, subtreeNodes, signedTxBytesMap); err != nil {
		return nil, fmt.Errorf("failed to update DB: %w", err)
	}

	if err := h.sendGossip(ctx, subtreeNodes, signedTxBytesMap); err != nil {
		return nil, fmt.Errorf("failed to send gossip: %w", err)
	}

	return &pbssp.ReSignSubtreeResponse{
		NodeSignatures: responseMap,
	}, nil
}

func (h *ReSignSubtreeHandler) buildSubtreeNodes(
	parentNode *ent.TreeNode,
	leftChainIDs, rightChainIDs []uuid.UUID,
	chainNodeMap map[uuid.UUID]*ent.TreeNode,
) []subtreeNode {
	var nodes []subtreeNode
	nodes = append(nodes, subtreeNode{node: parentNode, isParent: true})

	for i, id := range leftChainIDs {
		n := chainNodeMap[id]
		nodes = append(nodes, subtreeNode{node: n, isLeaf: i == len(leftChainIDs)-1})
	}
	for i, id := range rightChainIDs {
		n := chainNodeMap[id]
		nodes = append(nodes, subtreeNode{node: n, isLeaf: i == len(rightChainIDs)-1})
	}
	return nodes
}

// getPrevOutputForChainNode returns the correct prevOutput for a chain node.
// For the first node in each chain, this is the split tx output at the child's vout.
// For deeper chain nodes, this is always TxOut[0] of the preceding node's tx.
func (h *ReSignSubtreeHandler) getPrevOutputForChainNode(
	node *ent.TreeNode,
	parentNode *ent.TreeNode,
	constructedNodeTxs map[uuid.UUID]*wire.MsgTx,
	leftChainIDs, rightChainIDs []uuid.UUID,
	children []*ent.TreeNode,
) (*wire.TxOut, error) {
	splitTx := constructedNodeTxs[parentNode.ID]
	if splitTx == nil {
		return nil, fmt.Errorf("split tx not found for parent %s", parentNode.ID)
	}

	// First node in left chain → split tx output at children[0].Vout
	if len(leftChainIDs) > 0 && node.ID == leftChainIDs[0] {
		if int(children[0].Vout) >= len(splitTx.TxOut) {
			return nil, fmt.Errorf("split tx has %d outputs but left child Vout is %d", len(splitTx.TxOut), children[0].Vout)
		}
		return splitTx.TxOut[children[0].Vout], nil
	}
	// First node in right chain → split tx output at children[1].Vout
	if len(rightChainIDs) > 0 && node.ID == rightChainIDs[0] {
		if int(children[1].Vout) >= len(splitTx.TxOut) {
			return nil, fmt.Errorf("split tx has %d outputs but right child Vout is %d", len(splitTx.TxOut), children[1].Vout)
		}
		return splitTx.TxOut[children[1].Vout], nil
	}

	// Deeper chain node → TxOut[0] of the preceding node in the chain
	for i, id := range leftChainIDs {
		if id == node.ID && i > 0 {
			prevTx := constructedNodeTxs[leftChainIDs[i-1]]
			if prevTx == nil {
				return nil, fmt.Errorf("prev tx not found for node %s in left chain", node.ID)
			}
			return prevTx.TxOut[0], nil
		}
	}
	for i, id := range rightChainIDs {
		if id == node.ID && i > 0 {
			prevTx := constructedNodeTxs[rightChainIDs[i-1]]
			if prevTx == nil {
				return nil, fmt.Errorf("prev tx not found for node %s in right chain", node.ID)
			}
			return prevTx.TxOut[0], nil
		}
	}

	return nil, fmt.Errorf("node %s not found in either chain", node.ID)
}

func (h *ReSignSubtreeHandler) buildSplitTxSigningJobs(
	node *ent.TreeNode,
	keyshare *ent.SigningKeyshare,
	prevOutput *wire.TxOut,
	children []*ent.TreeNode,
	nodeJobs *pbssp.NodeSigningJobs,
) ([]*helper.SigningJobWithPregeneratedNonce, error) {
	if len(nodeJobs.SigningJobs) != 1 {
		return nil, fmt.Errorf("split node expects exactly 1 signing job, got %d", len(nodeJobs.SigningJobs))
	}

	userJob := nodeJobs.SigningJobs[0]
	tx, err := common.TxFromRawTxBytes(userJob.RawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse split tx: %w", err)
	}
	if tx.TxIn[0].Sequence != spark.ZeroSequence {
		return nil, fmt.Errorf("split tx sequence must be ZeroSequence, got %d", tx.TxIn[0].Sequence)
	}
	if len(tx.TxOut) != 3 {
		return nil, fmt.Errorf("split tx must have 3 outputs (2 children + anchor), got %d", len(tx.TxOut))
	}

	job, err := helper.NewSigningJobWithPregeneratedNonce(userJob, keyshare, node.VerifyingPubkey, tx, prevOutput)
	if err != nil {
		return nil, err
	}
	return []*helper.SigningJobWithPregeneratedNonce{job}, nil
}

func (h *ReSignSubtreeHandler) buildIntermediateSigningJobs(
	node *ent.TreeNode,
	keyshare *ent.SigningKeyshare,
	prevOutput *wire.TxOut,
	nodeJobs *pbssp.NodeSigningJobs,
) ([]*helper.SigningJobWithPregeneratedNonce, error) {
	if len(nodeJobs.SigningJobs) != 1 {
		return nil, fmt.Errorf("intermediate node expects exactly 1 signing job, got %d", len(nodeJobs.SigningJobs))
	}

	userJob := nodeJobs.SigningJobs[0]
	tx, err := common.TxFromRawTxBytes(userJob.RawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intermediate node_tx: %w", err)
	}
	if tx.TxIn[0].Sequence != spark.ZeroSequence {
		return nil, fmt.Errorf("intermediate node_tx sequence must be ZeroSequence, got %d", tx.TxIn[0].Sequence)
	}

	job, err := helper.NewSigningJobWithPregeneratedNonce(userJob, keyshare, node.VerifyingPubkey, tx, prevOutput)
	if err != nil {
		return nil, err
	}
	return []*helper.SigningJobWithPregeneratedNonce{job}, nil
}

func (h *ReSignSubtreeHandler) buildLeafSigningJobs(
	node *ent.TreeNode,
	keyshare *ent.SigningKeyshare,
	prevOutput *wire.TxOut,
	nodeJobs *pbssp.NodeSigningJobs,
) ([]*helper.SigningJobWithPregeneratedNonce, error) {
	if len(nodeJobs.SigningJobs) != 5 {
		return nil, fmt.Errorf("leaf node expects 5 signing jobs, got %d", len(nodeJobs.SigningJobs))
	}

	var jobs []*helper.SigningJobWithPregeneratedNonce

	// Job 0: node_tx (spends parent's output, InitialTimeLock = 2000)
	nodeTxJob := nodeJobs.SigningJobs[0]
	nodeTx, err := common.TxFromRawTxBytes(nodeTxJob.RawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf node_tx: %w", err)
	}
	if len(nodeTx.TxOut) == 0 {
		return nil, fmt.Errorf("leaf node_tx has no outputs")
	}
	job, err := helper.NewSigningJobWithPregeneratedNonce(nodeTxJob, keyshare, node.VerifyingPubkey, nodeTx, prevOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to create node_tx signing job: %w", err)
	}
	jobs = append(jobs, job)

	// Job 1: refund_tx (spends node_tx[0])
	refundTxJob := nodeJobs.SigningJobs[1]
	refundTx, err := common.TxFromRawTxBytes(refundTxJob.RawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf refund_tx: %w", err)
	}
	job, err = helper.NewSigningJobWithPregeneratedNonce(refundTxJob, keyshare, node.VerifyingPubkey, refundTx, nodeTx.TxOut[0])
	if err != nil {
		return nil, fmt.Errorf("failed to create refund_tx signing job: %w", err)
	}
	jobs = append(jobs, job)

	// Job 2: direct_tx (spends parent's output)
	directTxJob := nodeJobs.SigningJobs[2]
	directTx, err := common.TxFromRawTxBytes(directTxJob.RawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf direct_tx: %w", err)
	}
	if len(directTx.TxOut) == 0 {
		return nil, fmt.Errorf("leaf direct_tx has no outputs")
	}
	job, err = helper.NewSigningJobWithPregeneratedNonce(directTxJob, keyshare, node.VerifyingPubkey, directTx, prevOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to create direct_tx signing job: %w", err)
	}
	jobs = append(jobs, job)

	// Job 3: direct_refund_tx (spends direct_tx[0])
	directRefundTxJob := nodeJobs.SigningJobs[3]
	directRefundTx, err := common.TxFromRawTxBytes(directRefundTxJob.RawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf direct_refund_tx: %w", err)
	}
	job, err = helper.NewSigningJobWithPregeneratedNonce(directRefundTxJob, keyshare, node.VerifyingPubkey, directRefundTx, directTx.TxOut[0])
	if err != nil {
		return nil, fmt.Errorf("failed to create direct_refund_tx signing job: %w", err)
	}
	jobs = append(jobs, job)

	// Job 4: direct_from_cpfp_refund_tx (spends node_tx[0])
	directFromCpfpJob := nodeJobs.SigningJobs[4]
	directFromCpfpTx, err := common.TxFromRawTxBytes(directFromCpfpJob.RawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf direct_from_cpfp_refund_tx: %w", err)
	}
	job, err = helper.NewSigningJobWithPregeneratedNonce(directFromCpfpJob, keyshare, node.VerifyingPubkey, directFromCpfpTx, nodeTx.TxOut[0])
	if err != nil {
		return nil, fmt.Errorf("failed to create direct_from_cpfp_refund_tx signing job: %w", err)
	}
	jobs = append(jobs, job)

	return jobs, nil
}

func (h *ReSignSubtreeHandler) updateDBWithSignedTxs(
	ctx context.Context,
	subtreeNodes []subtreeNode,
	signedTxBytesMap map[string][][]byte,
) error {
	for _, sn := range subtreeNodes {
		nodeIDStr := sn.node.ID.String()
		txs := signedTxBytesMap[nodeIDStr]

		if sn.isParent || !sn.isLeaf {
			if len(txs) < 1 {
				return fmt.Errorf("no signed txs for node %s", nodeIDStr)
			}
			_, err := sn.node.Update().
				SetRawTx(txs[0]).
				ClearRawRefundTx().
				ClearDirectTx().
				ClearDirectRefundTx().
				ClearDirectFromCpfpRefundTx().
				Save(ctx)
			if err != nil {
				return fmt.Errorf("failed to update node %s: %w", nodeIDStr, err)
			}
		} else {
			if len(txs) < 5 {
				return fmt.Errorf("expected 5 signed txs for leaf %s, got %d", nodeIDStr, len(txs))
			}
			// Only leaf nodes get status set to AVAILABLE after re-signing.
			_, err := sn.node.Update().
				SetRawTx(txs[0]).
				SetRawRefundTx(txs[1]).
				SetDirectTx(txs[2]).
				SetDirectRefundTx(txs[3]).
				SetDirectFromCpfpRefundTx(txs[4]).
				SetStatus(st.TreeNodeStatusAvailable).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("failed to update leaf node %s: %w", nodeIDStr, err)
			}
		}
	}
	return nil
}

func (h *ReSignSubtreeHandler) sendGossip(
	ctx context.Context,
	subtreeNodes []subtreeNode,
	signedTxBytesMap map[string][][]byte,
) error {
	var internalNodes []*pbinternal.TreeNode

	for _, sn := range subtreeNodes {
		nodeIDStr := sn.node.ID.String()
		txs := signedTxBytesMap[nodeIDStr]

		internalNode := &pbinternal.TreeNode{Id: nodeIDStr}
		if len(txs) > 0 {
			internalNode.RawTx = txs[0]
		}
		if sn.isLeaf && len(txs) >= 5 {
			internalNode.RawRefundTx = txs[1]
			internalNode.DirectTx = txs[2]
			internalNode.DirectRefundTx = txs[3]
			internalNode.DirectFromCpfpRefundTx = txs[4]
		}
		internalNodes = append(internalNodes, internalNode)
	}

	selection := &helper.OperatorSelection{Option: helper.OperatorSelectionOptionExcludeSelf}
	participants, err := selection.OperatorIdentifierList(h.config)
	if err != nil {
		return fmt.Errorf("failed to get operator identifiers: %w", err)
	}

	sendGossipHandler := NewSendGossipHandler(h.config)
	_, err = sendGossipHandler.CreateCommitAndSendGossipMessage(ctx, &pbgossip.GossipMessage{
		Message: &pbgossip.GossipMessage_FinalizeTreeNode{
			FinalizeTreeNode: &pbgossip.GossipMessageFinalizeTreeNode{
				Nodes: internalNodes,
			},
		},
	}, participants)
	return err
}
