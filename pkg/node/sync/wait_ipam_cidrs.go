// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sync

import (
	"context"
	"fmt"
	"slices"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

func (ini *localNodeSynchronizer) allocationCIDRsAvailable(n *nodeTypes.Node) error {
	if ini.Config.K8sRequireIPv4PodCIDR && n.IPv4AllocCIDR == nil {
		return fmt.Errorf("required IPv4 PodCIDR not available")
	}
	if ini.Config.K8sRequireIPv6PodCIDR && n.IPv6AllocCIDR == nil {
		return fmt.Errorf("required IPv6 PodCIDR not available")
	}

	return nil
}

func (ini *localNodeSynchronizer) waitForNodeIPAMAllocationCIDROnK8sNode(ctx context.Context) *nodeTypes.Node {
	for event := range ini.K8sLocalNode.Events(ctx) {
		if event.Kind == resource.Upsert {
			n := k8s.ParseNode(ini.Logger, event.Object, source.Unspec)
			ini.Logger.Info("Retrieved local node information from kubernetes Node")

			if err := ini.allocationCIDRsAvailable(n); err != nil {
				ini.Logger.Warn("Waiting for k8s node information", logfields.Error, err)
				event.Done(nil)
				continue
			}

			event.Done(nil)
			return n
		}

		event.Done(nil)
	}

	return nil
}

func (ini *localNodeSynchronizer) waitForNodeIPAMAllocationCIDROnCiliumNode(ctx context.Context) *nodeTypes.Node {
	for event := range ini.K8sCiliumLocalNode.Events(ctx) {
		if event.Kind == resource.Upsert {
			n := nodeTypes.ParseCiliumNode(event.Object)
			ini.Logger.Info("Retrieved local node information from cilium node")

			if err := ini.allocationCIDRsAvailable(&n); err != nil {
				ini.Logger.Warn("Waiting for k8s node information", logfields.Error, err)
				event.Done(nil)
				continue
			}

			event.Done(nil)
			return &n
		}

		event.Done(nil)
	}

	return nil
}

// useNodeAllocationCIDR sets the ipv4-range and ipv6-range values values from the
// addresses defined in the given node.
func (ini *localNodeSynchronizer) useNodeAllocationCIDR(store *node.LocalNodeStore, n *nodeTypes.Node) {
	if n.IPv4AllocCIDR != nil && ini.Config.EnableIPv4 {
		store.Update(func(ln *node.LocalNode) {
			ln.IPv4AllocCIDR = n.IPv4AllocCIDR
		})
	}
	if n.IPv6AllocCIDR != nil && ini.Config.EnableIPv6 {
		store.Update(func(ln *node.LocalNode) {
			ln.IPv6AllocCIDR = n.IPv6AllocCIDR
		})
	}
}

// WaitForNodeIPAMAllocationCIDR will block and wait until the nodes IPAM allocation CIDR is available
// via CiliumNode or Kubernetes Node resource.
func (ini *localNodeSynchronizer) WaitForNodeIPAMAllocationCIDR(ctx context.Context, store *node.LocalNodeStore) error {
	// If no CIDR is required, retrieving the node information is optional.
	// At this point it's not clear whether the device auto-detection will
	// happen, as initKubeProxyReplacementOptions() might disable BPF NodePort.
	// Anyway, to be on the safe side, don't give up waiting for a (Cilium)Node
	// self object.
	//
	// If node information is optional, let's wait 10 seconds only.
	// It node information is required, wait indefinitely.
	if !ini.Config.K8sRequireIPv4PodCIDR && !ini.Config.K8sRequireIPv6PodCIDR {
		newCtx, cancel := context.WithTimeout(ctx, time.Second*10)
		ctx = newCtx
		defer cancel()
	}

	var n *nodeTypes.Node
	if slices.Contains([]string{ipamOption.IPAMClusterPool, ipamOption.IPAMMultiPool}, ini.Config.IPAM) {
		n = ini.waitForNodeIPAMAllocationCIDROnCiliumNode(ctx)
	} else {
		n = ini.waitForNodeIPAMAllocationCIDROnK8sNode(ctx)
	}

	if n == nil {
		// if node resource could not be received, fail if PodCIDR requirement has been requested
		if ini.Config.K8sRequireIPv4PodCIDR || ini.Config.K8sRequireIPv6PodCIDR {
			return fmt.Errorf("unable to derive PodCIDR via Node or CiliumNode resource")
		}

		return nil
	}

	ini.Logger.Info("Received local node IPAM allocation CIDR",
		logfields.V4Prefix, n.IPv4AllocCIDR,
		logfields.V6Prefix, n.IPv6AllocCIDR,
	)

	ini.useNodeAllocationCIDR(store, n)

	// Annotate addresses will occur later since the user might
	// want to specify them manually
	return nil
}
