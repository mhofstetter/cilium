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

	cell.Provide(newServer),
)

type xdsServerParams struct {
	cell.In

	Lifecycle       cell.Lifecycle
	RestorerPromise promise.Promise[endpointstate.Restorer]
}

func newServer(params xdsServerParams) (*Server, error) {
	server := &Server{}

	// Start serving resources to external Envoy proxy only after all endpoints have been
	// restored.
	if option.Config.ExternalEnvoyProxy && option.Config.RestoreState {
		server.restorerPromise = params.RestorerPromise
	}
	return server, nil
}
