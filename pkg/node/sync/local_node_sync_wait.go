// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sync

import (
	"context"
	"errors"
	"fmt"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

func (ini *localNodeSynchronizer) retrieveNodeInformation(ctx context.Context) *nodeTypes.Node {
	validateCIDRConfigured := func(n *nodeTypes.Node) error {
		if option.Config.K8sRequireIPv4PodCIDR && n.IPv4AllocCIDR == nil {
			return fmt.Errorf("required IPv4 PodCIDR not available")
		}
		if option.Config.K8sRequireIPv6PodCIDR && n.IPv6AllocCIDR == nil {
			return fmt.Errorf("required IPv6 PodCIDR not available")
		}
		return nil
	}

	if option.Config.IPAM == ipamOption.IPAMClusterPool ||
		option.Config.IPAM == ipamOption.IPAMMultiPool {
		for event := range ini.K8sCiliumLocalNode.Events(ctx) {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				ini.Logger.Error("Timeout while waiting for CiliumNode resource: API server connection issue", logfields.NodeName, nodeTypes.GetName())
				break
			}
			if event.Kind == resource.Upsert {
				n := nodeTypes.ParseCiliumNode(event.Object)
				ini.Logger.Info("Retrieved node information from cilium node", logfields.NodeName, n.Name)
				if err := validateCIDRConfigured(&n); err != nil {
					ini.Logger.Warn("Waiting for k8s node information", logfields.Error, err)
				} else {
					event.Done(nil)
					return &n
				}
			}
			event.Done(nil)
		}
	} else {
		for event := range ini.K8sLocalNode.Events(ctx) {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				ini.Logger.Error("Timeout while waiting for Node resource: API server connection issue", logfields.NodeName, nodeTypes.GetName())
				break
			}
			if event.Kind == resource.Upsert {
				n := k8s.ParseNode(ini.Logger, event.Object, source.Unspec)
				ini.Logger.Info("Retrieved node information from kubernetes node", logfields.NodeName, n.Name)
				if err := validateCIDRConfigured(n); err != nil {
					ini.Logger.Warn("Waiting for k8s node information", logfields.Error, err)
				} else {
					event.Done(nil)
					return n
				}
			}
			event.Done(nil)
		}
	}

	return nil
}

// useNodeCIDR sets the ipv4-range and ipv6-range values values from the
// addresses defined in the given k8s node on the local node.
func (ini *localNodeSynchronizer) useNodeCIDR(localNode *node.LocalNode, n *nodeTypes.Node) {
	if n.IPv4AllocCIDR != nil && option.Config.EnableIPv4 {
		localNode.IPv4AllocCIDR = n.IPv4AllocCIDR
	}
	if n.IPv6AllocCIDR != nil && option.Config.EnableIPv6 {
		localNode.IPv6AllocCIDR = n.IPv6AllocCIDR
	}
}

// WaitForNodeInformationFromK8s retrieves the node information via the CiliumNode or
// Kubernetes Node resource. This function will block until the information is
// received.
func (ini *localNodeSynchronizer) waitForNodeInformationFromK8s(ctx context.Context, localNode *node.LocalNode) error {
	requireIPv4CIDR := option.Config.K8sRequireIPv4PodCIDR
	requireIPv6CIDR := option.Config.K8sRequireIPv6PodCIDR
	// If no CIDR is required, retrieving the node information is
	// optional
	// At this point it's not clear whether the device auto-detection will
	// happen, as initKubeProxyReplacementOptions() might disable BPF NodePort.
	// Anyway, to be on the safe side, don't give up waiting for a (Cilium)Node
	// self object.
	isNodeInformationOptional := (!requireIPv4CIDR && !requireIPv6CIDR)
	// If node information is optional, let's wait 10 seconds only.
	// It node information is required, wait indefinitely.
	if isNodeInformationOptional {
		newCtx, cancel := context.WithTimeout(ctx, time.Second*10)
		ctx = newCtx
		defer cancel()
	}

	if k8sNode := ini.retrieveNodeInformation(ctx); k8sNode != nil {
		nodeIP4 := k8sNode.GetNodeIP(false)
		nodeIP6 := k8sNode.GetNodeIP(true)
		k8sNodeIP := k8sNode.GetK8sNodeIP()

		ini.Logger.Info(
			"Received own node information from API server",
			logfields.NodeName, k8sNode.Name,
			logfields.Labels, k8sNode.Labels,
			logfields.IPv4, nodeIP4,
			logfields.IPv6, nodeIP6,
			logfields.V4Prefix, k8sNode.IPv4AllocCIDR,
			logfields.V6Prefix, k8sNode.IPv6AllocCIDR,
			logfields.K8sNodeIP, k8sNodeIP,
		)

		if option.Config.EnableIPv6 && nodeIP6 == nil {
			ini.Logger.Warn("IPv6 is enabled, but Cilium cannot find the IPv6 address for this node. " +
				"This may cause connectivity disruption for Endpoints that attempt to communicate using IPv6")
		}

		ini.useNodeCIDR(localNode, k8sNode)
	} else {
		// if node resource could not be received, fail if
		// PodCIDR requirement has been requested
		if requireIPv4CIDR || requireIPv6CIDR {
			return fmt.Errorf("unable to derive PodCIDR via Node or CiliumNode resource")
		}
	}

	// Annotate addresses will occur later since the user might
	// want to specify them manually
	return nil
}
