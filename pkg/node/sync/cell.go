// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sync

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var LocalNodeSyncCell = cell.Module(
	"local-node-sync",
	"Syncs the LocalNodeStore with the K8s Node",

	cell.Config(config{
		AnnotateK8sNode: false,
	}),
	cell.Provide(newNodeSyncConfig),

	// Provides a newLocalNodeSynchronizer that is invoked when LocalNodeStore is started.
	// This fills in the initial state before it is accessed by other sub-systems.
	// Then, it takes care of keeping selected fields (e.g., labels, annotations)
	// synchronized with the corresponding kubernetes object.
	cell.Provide(newLocalNodeSynchronizer),

	// Registers the LocalNodeAnnotator that annotate the K8s Node resource
	// with relevant annotations if configured.
	cell.Invoke(registerLocalNodeAnnotator),
)

type config struct {
	AnnotateK8sNode bool
}

func (r config) Flags(flags *pflag.FlagSet) {
	flags.Bool("annotate-k8s-node", r.AnnotateK8sNode, "Specifies whether to annotate the kubernetes nodes or not")
}

// NodeSyncConfig provides the config to other modules
type NodeSyncConfig struct {
	annotateK8sNode bool
}

func newNodeSyncConfig(config config) NodeSyncConfig {
	return NodeSyncConfig{
		annotateK8sNode: config.AnnotateK8sNode,
	}
}

func (r *NodeSyncConfig) AnnotateK8sNode() bool {
	return r.annotateK8sNode
}
