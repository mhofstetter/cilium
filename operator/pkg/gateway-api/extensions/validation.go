// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package extensions

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/hive/cell"
)

type RouteValidationInput struct {
	RouteNamespace string
	ExtensionRef   ExtensionRef
}

type RouteValidationResult struct {
	Continue   bool
	Conditions []metav1.Condition
}

// ContinueRouteValidation returns a validation result that allows the caller
// to keep evaluating the route while contributing additional conditions.
func ContinueRouteValidation(conditions ...metav1.Condition) RouteValidationResult {
	return RouteValidationResult{
		Continue:   true,
		Conditions: conditions,
	}
}

type RouteValidationExtension interface {
	// Supports reports whether this extension owns the referenced object for the
	// given route kind.
	Supports(kind RouteKind, ref ExtensionRef) bool

	// Validate checks whether an extension reference is acceptable for a route.
	//
	// Purpose:
	// - validate that an ExtensionRef is resolvable and semantically acceptable
	// - contribute route status conditions such as ResolvedRefs
	//
	// Contract:
	// - called during route status validation before ingestion
	// - may read Kubernetes objects through extension-owned dependencies
	// - must not mutate the internal model or generated Envoy resources
	// - returns conditions for the caller to merge into route status
	Validate(ctx context.Context, in RouteValidationInput) (RouteValidationResult, error)
}

type RouteValidationOut struct {
	cell.Out

	RouteValidationExtension RouteValidationExtension `group:"gateway-api-route-validation-extensions"`
}
