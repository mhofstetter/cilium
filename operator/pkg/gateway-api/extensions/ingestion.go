// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package extensions

import (
	"context"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/operator/pkg/model"
)

type RouteFilterExtRefIngestionInput struct {
	RouteNamespace string
	ExtensionRef   ExtensionRef
	RouteModel     *model.HTTPRoute
}

type RouteFilterExtRefIngestionExtension interface {
	// Supports reports whether this extension owns the referenced object for the
	// given route kind.
	Supports(kind RouteKind, ref ExtensionRef) bool

	// ApplyToHTTPRoute converts extension-specific route data into internal
	// model data for an HTTPRoute-backed model.HTTPRoute.
	//
	// Purpose:
	// - use extension-owned dependencies to derive reduced model payload
	// - attach reduced extension payload to the internal model
	//
	// Contract:
	// - called during Gateway API ingestion for each matching HTTPRoute ExtensionRef
	// - may mutate only the provided model route
	// - must not write status or generate Envoy resources directly
	ApplyToHTTPRoute(ctx context.Context, in RouteFilterExtRefIngestionInput) error

	// ApplyToGRPCRoute converts extension-specific route data into internal
	// model data for a GRPCRoute-backed model.HTTPRoute.
	//
	// Purpose:
	// - use extension-owned dependencies to derive reduced model payload
	// - attach reduced extension payload to the internal model
	//
	// Contract:
	// - called during Gateway API ingestion for each matching GRPCRoute ExtensionRef
	// - may mutate only the provided model route
	// - must not write status or generate Envoy resources directly
	ApplyToGRPCRoute(ctx context.Context, in RouteFilterExtRefIngestionInput) error
}

type RouteFilterExtRefIngestionOut struct {
	cell.Out

	RouteFilterExtRefIngestionExtension RouteFilterExtRefIngestionExtension `group:"gateway-api-route-filter-ext-ref-ingestion-extensions"`
}
