// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package extensions

import (
	"github.com/cilium/hive/cell"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"

	"github.com/cilium/cilium/operator/pkg/model"
)

type HTTPRouteTranslationExtension interface {
	// MutateHTTPRoute applies extension-specific translation to an Envoy HTTP
	// route derived from the internal model.
	//
	// Purpose:
	// - read extension payload previously attached to model.HTTPRoute
	// - mutate the generated Envoy route config for that model route
	//
	// Contract:
	// - called after base HTTP route translation
	// - should depend only on model data, not fresh Kubernetes lookups
	// - may mutate only the provided Envoy route
	MutateHTTPRoute(route model.HTTPRoute, envoyRoute *envoy_config_route_v3.Route)
}

type HTTPRouteTranslationOut struct {
	cell.Out

	HTTPRouteTranslationExtension HTTPRouteTranslationExtension `group:"gateway-api-http-route-translation-extensions"`
}
