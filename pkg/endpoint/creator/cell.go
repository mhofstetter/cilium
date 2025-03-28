// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package creator

import (
	"github.com/cilium/hive/cell"
)

// Cell provides the EndpointCreator which creates endpoints.
var Cell = cell.Module(
	"endpoint-creator",
	"Creates endpoints",

	cell.Provide(newEndpointCreator),
)
