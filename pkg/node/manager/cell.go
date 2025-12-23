// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/backoff"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// Cell provides the NodeManager, which manages information about Cilium nodes
// in the cluster and informs other modules of changes to node configuration.
var Cell = cell.Module(
	"node-manager",
	"Manages the collection of Cilium nodes",
	cell.Provide(newAllNodeManager),
	cell.Provide(newClusterSizeDependantIntervalCalculator),
	cell.Provide(newGetClusterNodesRestAPIHandler),
	cell.Provide(newNodeConfigNotifier),
	metrics.Metric(NewNodeMetrics),
)

// Notifier is the interface the wraps Subscribe and Unsubscribe. An
// implementation of this interface notifies subscribers of nodes being added,
// updated or deleted.
type Notifier interface {
	// Subscribe adds the given NodeHandler to the list of subscribers that are
	// notified of node changes. Upon call to this method, the NodeHandler is
	// being notified of all nodes that are already in the cluster by calling
	// the NodeHandler's NodeAdd callback.
	Subscribe(datapath.NodeHandler)

	// Unsubscribe removes the given NodeHandler from the list of subscribers.
	Unsubscribe(datapath.NodeHandler)
}

type NodeManager interface {
	Notifier

	// GetNodes returns a copy of all the nodes as a map from Identity to Node.
	GetNodes() map[types.Identity]types.Node

	// GetNodeIdentities returns a list of all node identities store in node
	// manager.
	GetNodeIdentities() []types.Identity

	// NodeUpdated is called when the store detects a change in node
	// information
	NodeUpdated(n types.Node)

	// NodeDeleted is called when the store detects a deletion of a node
	NodeDeleted(n types.Node)

	// NodeSync is called when the store completes the initial nodes listing
	NodeSync()
	// MeshNodeSync is called when the store completes the initial nodes listing including meshed nodes
	MeshNodeSync()

	// SetPrefixClusterMutatorFn allows to inject a custom prefix cluster mutator.
	// The mutator may then be applied to the PrefixCluster(s) using cmtypes.PrefixClusterFrom,
	// cmtypes.PrefixClusterFromCIDR and the like.
	SetPrefixClusterMutatorFn(mutator func(*types.Node) []cmtypes.PrefixClusterOpts)
}

func newAllNodeManager(in struct {
	cell.In
	Logger                        *slog.Logger
	TunnelConf                    tunnel.Config
	Lifecycle                     cell.Lifecycle
	IPCache                       *ipcache.IPCache
	IPSetMgr                      ipset.Manager
	IPSetFilter                   IPSetFilterFn `optional:"true"`
	NodeMetrics                   *nodeMetrics
	ClusterSizeIntervalCalculator *clusterSizeDependantIntervalCalculator
	Health                        cell.Health
	JobGroup                      job.Group
	DB                            *statedb.DB
	Devices                       statedb.Table[*tables.Device]
	WGConfig                      wgTypes.WireguardConfig
},
) (NodeManager, error) {
	mngr, err := New(in.Logger, option.Config, in.TunnelConf, in.IPCache, in.IPSetMgr, in.IPSetFilter, in.NodeMetrics, in.Health, in.JobGroup, in.DB, in.Devices, in.WGConfig)
	if err != nil {
		return nil, err
	}

	mngr.Subscribe(in.ClusterSizeIntervalCalculator)

	in.Lifecycle.Append(mngr)
	return mngr, nil
}

func newClusterSizeDependantIntervalCalculator() (*clusterSizeDependantIntervalCalculator, ClusterSizeDependantIntervalCalculator) {
	c := &clusterSizeDependantIntervalCalculator{}
	return c, c
}

type ClusterSizeDependantIntervalCalculator interface {
	// ClusterSizeDependantInterval returns a time.Duration that is dependent on
	// the cluster size, i.e. the number of nodes that have been discovered. This
	// can be used to control sync intervals of shared or centralized resources to
	// avoid overloading these resources as the cluster grows.
	ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration
}

var _ ClusterSizeDependantIntervalCalculator = (*clusterSizeDependantIntervalCalculator)(nil)

var _ datapath.NodeHandler = (*clusterSizeDependantIntervalCalculator)(nil)

type clusterSizeDependantIntervalCalculator struct {
	nodeCount atomic.Int64
}

func (c *clusterSizeDependantIntervalCalculator) AllNodeValidateImplementation() {}

func (c *clusterSizeDependantIntervalCalculator) Name() string {
	return "clustersize-dependant-interval-calculator"
}

func (c *clusterSizeDependantIntervalCalculator) NodeAdd(newNode types.Node) error {
	c.nodeCount.Add(1)
	return nil
}

func (c *clusterSizeDependantIntervalCalculator) NodeDelete(node types.Node) error {
	c.nodeCount.Add(-1)
	return nil
}

func (c *clusterSizeDependantIntervalCalculator) NodeUpdate(oldNode types.Node, newNode types.Node) error {
	return nil
}

func (c *clusterSizeDependantIntervalCalculator) NodeValidateImplementation(node types.Node) error {
	return nil
}

// ClusterSizeDependantInterval returns a time.Duration that is dependant on
// the cluster size, i.e. the number of nodes that have been discovered. This
// can be used to control sync intervals of shared or centralized resources to
// avoid overloading these resources as the cluster grows.
//
// Example sync interval with baseInterval = 1 * time.Minute
//
// nodes | sync interval
// ------+-----------------
// 1     |   41.588830833s
// 2     | 1m05.916737320s
// 4     | 1m36.566274746s
// 8     | 2m11.833474640s
// 16    | 2m49.992800643s
// 32    | 3m29.790453687s
// 64    | 4m10.463236193s
// 128   | 4m51.588744261s
// 256   | 5m32.944565093s
// 512   | 6m14.416550710s
// 1024  | 6m55.946873494s
// 2048  | 7m37.506428894s
// 4096  | 8m19.080616652s
// 8192  | 9m00.662124608s
// 16384 | 9m42.247293667s
func (c *clusterSizeDependantIntervalCalculator) ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration {
	return backoff.ClusterSizeDependantInterval(baseInterval, int(c.nodeCount.Load()))
}
