// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package extensions

import (
	"sigs.k8s.io/controller-runtime/pkg/builder"

	"github.com/cilium/hive/cell"
)

type ControllerExtension interface {
	// RegisterGatewayController extends the main Gateway controller setup.
	//
	// Purpose:
	// - register watches, field indexes, and enqueue logic for extension-owned resources
	//
	// Contract:
	// - called once during controller setup
	// - may mutate the provided controller builder by adding watches
	// - must not rely on per-reconcile state
	RegisterGatewayController(gatewayBuilder *builder.Builder) error
}

type ControllerOut struct {
	cell.Out

	ControllerExtension ControllerExtension `group:"gateway-api-controller-extensions"`
}
