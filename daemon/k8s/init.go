// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package k8s abstracts all Kubernetes specific behaviour
package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

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

func allocationCIDRsAvailable(n *nodeTypes.Node) error {
	if option.Config.K8sRequireIPv4PodCIDR && n.IPv4AllocCIDR == nil {
		return fmt.Errorf("required IPv4 PodCIDR not available")
	}
	if option.Config.K8sRequireIPv6PodCIDR && n.IPv6AllocCIDR == nil {
		return fmt.Errorf("required IPv6 PodCIDR not available")
	}

	return nil
}

func waitForNodeIPAMAllocationCIDROnK8sNode(ctx context.Context, log *slog.Logger, localNodeResource LocalNodeResource) *nodeTypes.Node {
	for event := range localNodeResource.Events(ctx) {
		if event.Kind == resource.Upsert {
			n := k8s.ParseNode(log, event.Object, source.Unspec)
			log.Info("Retrieved local node information from kubernetes Node")

			if err := allocationCIDRsAvailable(n); err != nil {
				log.Warn("Waiting for k8s node information", logfields.Error, err)
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

func waitForNodeIPAMAllocationCIDROnCiliumNode(ctx context.Context, log *slog.Logger, localCiliumNodeResource LocalCiliumNodeResource) *nodeTypes.Node {
	for event := range localCiliumNodeResource.Events(ctx) {
		if event.Kind == resource.Upsert {
			n := nodeTypes.ParseCiliumNode(event.Object)
			log.Info("Retrieved local node information from cilium node")

			if err := allocationCIDRsAvailable(&n); err != nil {
				log.Warn("Waiting for k8s node information", logfields.Error, err)
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
func useNodeAllocationCIDR(n *nodeTypes.Node) {
	if n.IPv4AllocCIDR != nil && option.Config.EnableIPv4 {
		node.SetIPv4AllocRange(n.IPv4AllocCIDR)
	}
	if n.IPv6AllocCIDR != nil && option.Config.EnableIPv6 {
		node.SetIPv6NodeRange(n.IPv6AllocCIDR)
	}
}

// WaitForNodeIPAMAllocationCIDR will block and wait until the nodes IPAM allocation CIDR is available
// via CiliumNode or Kubernetes Node resource.
func WaitForNodeIPAMAllocationCIDR(ctx context.Context, log *slog.Logger, localNode LocalNodeResource, localCiliumNode LocalCiliumNodeResource) error {
	// If no CIDR is required, retrieving the node information is optional.
	// At this point it's not clear whether the device auto-detection will
	// happen, as initKubeProxyReplacementOptions() might disable BPF NodePort.
	// Anyway, to be on the safe side, don't give up waiting for a (Cilium)Node
	// self object.
	//
	// If node information is optional, let's wait 10 seconds only.
	// It node information is required, wait indefinitely.
	if !option.Config.K8sRequireIPv4PodCIDR && !option.Config.K8sRequireIPv6PodCIDR {
		newCtx, cancel := context.WithTimeout(ctx, time.Second*10)
		ctx = newCtx
		defer cancel()
	}

	var n *nodeTypes.Node
	if slices.Contains([]string{ipamOption.IPAMClusterPool, ipamOption.IPAMMultiPool}, option.Config.IPAM) {
		n = waitForNodeIPAMAllocationCIDROnCiliumNode(ctx, log, localCiliumNode)
	} else {
		n = waitForNodeIPAMAllocationCIDROnK8sNode(ctx, log, localNode)
	}

	if n == nil {
		// if node resource could not be received, fail if PodCIDR requirement has been requested
		if option.Config.K8sRequireIPv4PodCIDR || option.Config.K8sRequireIPv6PodCIDR {
			return fmt.Errorf("unable to derive PodCIDR via Node or CiliumNode resource")
		}

		return nil
	}

	log.Info("Received local node IPAM allocation CIDR",
		logfields.V4Prefix, n.IPv4AllocCIDR,
		logfields.V6Prefix, n.IPv6AllocCIDR,
	)

	useNodeAllocationCIDR(n)

	// Annotate addresses will occur later since the user might
	// want to specify them manually
	return nil
}
