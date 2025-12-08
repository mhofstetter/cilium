// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the ctmap.Map which contains the connection tracking state.
var Cell = cell.Module(
	"ct-map",
	"eBPF map which manages connection tracking",

	cell.Provide(newCTMaps),
)

func newCTMaps(lifecycle cell.Lifecycle, daemonConfig *option.DaemonConfig, kprConfig kpr.KPRConfig, registry *metrics.Registry) bpf.MapOut[CTMaps] {
	InitMapInfo(registry, daemonConfig.EnableIPv4, daemonConfig.EnableIPv6, kprConfig.KubeProxyReplacement || daemonConfig.EnableBPFMasquerade)

	ctMaps := &ctMaps{}

	if daemonConfig.IPv4Enabled() {
		ctMaps.v4AnyMap = newMap(MapNameAny4Global, mapTypeIPv4AnyGlobal)
		ctMaps.v4TCPMap = newMap(MapNameTCP4Global, mapTypeIPv4TCPGlobal)
	}

	if daemonConfig.IPv6Enabled() {
		ctMaps.v6AnyMap = newMap(MapNameAny6Global, mapTypeIPv6AnyGlobal)
		ctMaps.v6TCPMap = newMap(MapNameTCP6Global, mapTypeIPv6TCPGlobal)
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return ctMaps.init()
		},
		OnStop: func(context cell.HookContext) error {
			return ctMaps.close()
		},
	})

	return bpf.NewMapOut(CTMaps(ctMaps))
}

// CTMaps provides access to the active connection tracking BPF maps.
type CTMaps interface {
	// ActiveMaps returns a slice of global CT maps that are used, depending
	// on whether IPv4 and/or IPv6 is configured.
	ActiveMaps() []*Map
}

type ctMaps struct {
	v4AnyMap *Map
	v4TCPMap *Map
	v6AnyMap *Map
	v6TCPMap *Map
}

var _ CTMaps = &ctMaps{}

func (r *ctMaps) ActiveMaps() []*Map {
	activeMaps := []*Map{}

	if r.v4AnyMap != nil {
		activeMaps = append(activeMaps, r.v4AnyMap)
	}

	if r.v4TCPMap != nil {
		activeMaps = append(activeMaps, r.v4TCPMap)
	}

	if r.v6AnyMap != nil {
		activeMaps = append(activeMaps, r.v6AnyMap)
	}

	if r.v6TCPMap != nil {
		activeMaps = append(activeMaps, r.v6TCPMap)
	}

	return activeMaps
}

func (r *ctMaps) init() error {
	if r.v4AnyMap != nil {
		if err := r.v4AnyMap.Map.OpenOrCreate(); err != nil {
			return fmt.Errorf("failed to open and create v4 ANY map: %w", err)
		}
	}

	if r.v4TCPMap != nil {
		if err := r.v4TCPMap.Map.OpenOrCreate(); err != nil {
			return fmt.Errorf("failed to open and create v4 TCP map: %w", err)
		}
	}

	if r.v6AnyMap != nil {
		if err := r.v6AnyMap.Map.OpenOrCreate(); err != nil {
			return fmt.Errorf("failed to open and create v6 any map: %w", err)
		}
	}

	if r.v6TCPMap != nil {
		if err := r.v6TCPMap.Map.OpenOrCreate(); err != nil {
			return fmt.Errorf("failed to open and create v6 TCP map: %w", err)
		}
	}

	return nil
}

func (r *ctMaps) close() error {
	if r.v4AnyMap != nil {
		if err := r.v4AnyMap.Map.Close(); err != nil {
			return fmt.Errorf("failed to close v4 ANY map: %w", err)
		}
	}

	if r.v4TCPMap != nil {
		if err := r.v4TCPMap.Map.Close(); err != nil {
			return fmt.Errorf("failed to close v4 TCP map: %w", err)
		}
	}

	if r.v6AnyMap != nil {
		if err := r.v6AnyMap.Map.Close(); err != nil {
			return fmt.Errorf("failed to close v6 any map: %w", err)
		}
	}

	if r.v6TCPMap != nil {
		if err := r.v6TCPMap.Map.Close(); err != nil {
			return fmt.Errorf("failed to close v6 TCP map: %w", err)
		}
	}

	return nil
}
