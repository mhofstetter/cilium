// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointstate

import (
	"context"

	"github.com/cilium/cilium/pkg/endpoint"
)

// Restorer wraps a method to wait for endpoints restoration.
type Restorer interface {
	// WaitForEndpointRestoreWithoutRegeneration blocks the caller until either the context is
	// cancelled or all the endpoints from a previous run have been restored.
	WaitForEndpointRestoreWithoutRegeneration(ctx context.Context) error

	// WaitForEndpointRestore blocks the caller until either the context is
	// cancelled or all the endpoints from a previous run have been restored and regenerated.
	WaitForEndpointRestore(ctx context.Context) error

	// WaitForInitialPolicy blocks the caller until either the context is
	// cancelled or initial policies of all restored endpoints have been computed.
	WaitForInitialPolicy(ctx context.Context) error

	// GetRestoredEndpoints returns the endpoints that have been restored
	// from disk - but haven't been successfully validated yet.
	GetRestoredEndpoints() map[uint16]*endpoint.Endpoint
}
