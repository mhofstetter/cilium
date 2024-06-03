// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

// Cell initializes and manages the Envoy xds server.
var Cell = cell.Module(
	"envoy-proxy-xds",
	"Envoy xDS cache and server",

	cell.Provide(newXDS),
)

type xdsServerParams struct {
	cell.In

	Lifecycle       cell.Lifecycle
	RestorerPromise promise.Promise[endpointstate.Restorer]
}

type XDS interface {
	NewServer(resourceTypes map[string]*ResourceTypeConfiguration) *Server

	// Restore returns 'true' if a restorer promise exists
	Restore() bool
}

type xds struct {
	// restorerPromise is initialized only if xDS server should wait sending any xDS resources
	// until all endpoints have been restored.
	restorerPromise promise.Promise[endpointstate.Restorer]
}

func (x *xds) Restore() bool {
	return x.restorerPromise != nil
}

func newXDS(params xdsServerParams) (XDS, error) {
	x := &xds{}

	// Start serving resources to external Envoy proxy only after all endpoints have been
	// restored.
	if option.Config.ExternalEnvoyProxy && option.Config.RestoreState {
		x.restorerPromise = params.RestorerPromise
	}
	return x, nil
}

// mockXDS is used for testing from multiple packages
func MockXDS() XDS {
	return &xds{}
}
