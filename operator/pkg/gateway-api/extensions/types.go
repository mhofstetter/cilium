// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package extensions

import gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

type RouteKind string

const (
	RouteKindHTTP RouteKind = "HTTPRoute"
	RouteKindGRPC RouteKind = "GRPCRoute"
	RouteKindTLS  RouteKind = "TLSRoute"
)

type ExtensionRef struct {
	Group string
	Kind  string
	Name  string
}

func ExtensionRefFromLocalObjectReference(ref *gatewayv1.LocalObjectReference) (ExtensionRef, bool) {
	if ref == nil {
		return ExtensionRef{}, false
	}

	return ExtensionRef{
		Group: string(ref.Group),
		Kind:  string(ref.Kind),
		Name:  string(ref.Name),
	}, true
}

func HTTPRouteExtensionRefs(rule gatewayv1.HTTPRouteRule) []ExtensionRef {
	var refs []ExtensionRef
	for _, filter := range rule.Filters {
		if filter.Type != gatewayv1.HTTPRouteFilterExtensionRef {
			continue
		}

		ref, ok := ExtensionRefFromLocalObjectReference(filter.ExtensionRef)
		if !ok {
			continue
		}
		refs = append(refs, ref)
	}
	return refs
}

func GRPCRouteExtensionRefs(rule gatewayv1.GRPCRouteRule) []ExtensionRef {
	var refs []ExtensionRef
	for _, filter := range rule.Filters {
		if filter.Type != gatewayv1.GRPCRouteFilterExtensionRef {
			continue
		}

		ref, ok := ExtensionRefFromLocalObjectReference(filter.ExtensionRef)
		if !ok {
			continue
		}
		refs = append(refs, ref)
	}
	return refs
}
