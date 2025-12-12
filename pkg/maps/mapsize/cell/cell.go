package mapsizecell

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/mapsize"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
)

// Cell provides the BPF map size config.
var Cell = cell.Module(
	"bpf-map-size-config",
	"BPF map size config",

	mapsize.ConfigCell,
	cell.Provide(newBPFMapSizeConfig),
)

// newBPFMapSizeConfig initializes and provides the BPFMapsSizeConfig by
// It initializes the underlying provider with the size of the bpf map entries
// of the dynamic tables.
//
// That's also the reason why this cell is in its own Go package. Otherwise
// there would be a cycle between the involved packages.
func newBPFMapSizeConfig(logger *slog.Logger, flags mapsize.BPFMapsSizeFlags) (mapsize.BPFMapsSizeConfig, error) {
	return mapsize.NewBPFMapsSizeConfig(
		logger,
		flags,

		// for the conntrack and NAT element size we assume the largest possible
		// key size, i.e. IPv6 keys
		ctmap.SizeofCtKey6Global+ctmap.SizeofCtEntry,
		nat.SizeofNatKey6+nat.SizeofNatEntry6,
		neighborsmap.SizeofNeighKey6+neighborsmap.SizeOfNeighValue,
		lbmaps.SizeofSockRevNat6Key+lbmaps.SizeofSockRevNat6Value,
	)
}
