// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

var DirectRoutingDeviceCell = cell.Module(
	"direct-routing-device",
	"Resolves user configuration to interface used for direct routing",

	cell.Provide(NewDirectRoutingDevice),
	cell.Config(DirectRoutingDeviceConfig{}),
)

func (c DirectRoutingDeviceConfig) Flags(flags *pflag.FlagSet) {
	flags.String(
		option.DirectRoutingDevice,
		"",
		"Device name used to connect nodes in direct routing mode (used by BPF NodePort, "+
			"BPF host routing; if empty, automatically set to a device with k8s "+
			"InternalIP/ExternalIP or with a default route)",
	)
}

type DirectRoutingDeviceConfig struct {
	DirectRoutingDevice string
}

type DirectRoutingDeviceParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Log       *slog.Logger
	Config    DirectRoutingDeviceConfig
	Node      *node.LocalNodeStore `optional:"true"`
	DB        *statedb.DB
	Devices   statedb.Table[*Device]
}

type DirectRoutingDevice struct {
	p *DirectRoutingDeviceParams
}

func NewDirectRoutingDevice(p DirectRoutingDeviceParams) DirectRoutingDevice {
	drd := DirectRoutingDevice{&p}

	previousDRDName := "n/a"

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			directRoutingDevice, _ := drd.Get(ctx, p.DB.ReadTxn())

			if directRoutingDevice == nil {
				p.Log.Info("No direct routing device detected")
				return nil
			}

			previousDRDName = directRoutingDevice.Name
			p.Log.Info("Direct routing device detected", logfields.DirectRoutingDevice, directRoutingDevice.Name)
			return nil
		},
	})

	p.JobGroup.Add(job.OneShot("direct-routing-device-change", func(ctx context.Context, _ cell.Health) error {
		for {
			directRoutingDevice, devicesChangedWatch := drd.Get(ctx, p.DB.ReadTxn())

			newDRDName := "n/a"
			if directRoutingDevice != nil {
				newDRDName = directRoutingDevice.Name
			}

			if previousDRDName != newDRDName {
				p.Log.Info("Changed direct routing device detected",
					logfields.Previous, previousDRDName,
					logfields.DirectRoutingDevice, newDRDName,
				)
			}
			previousDRDName = newDRDName

			select {
			case <-ctx.Done():
				return nil
			case <-devicesChangedWatch:
				// continue and check for changed direct routing device
			}
		}
	}))

	return drd
}

// Get returns the direct routing device and a channel which closes if the
// query invalidates. Can return a nil device, if no suitable device is found.
func (dr DirectRoutingDevice) Get(ctx context.Context, rxn statedb.ReadTxn) (*Device, <-chan struct{}) {
	var filter DeviceFilter
	if dr.p.Config.DirectRoutingDevice != "" {
		filter = DeviceFilter([]string{dr.p.Config.DirectRoutingDevice})
	}

	var device *Device
	devs, watch := SelectedDevices(dr.p.Devices, rxn)
	if filter.NonEmpty() {
		// User has defined a direct-routing device. Try to find the first matching
		// device.
		for _, dev := range devs {
			match, reverse := filter.Match(dev.Name)
			if match && !reverse {
				device = dev
				break
			}
		}
	} else if len(devs) == 1 {
		device = devs[0]
	}

	// Fallback to the device matching the K8s Node IP.
	if device == nil && dr.p.Node != nil {
		node, err := dr.p.Node.Get(ctx)
		if err == nil {
			nodeIP, ok := netipx.FromStdIP(node.GetK8sNodeIP())
			if ok {
				for _, dev := range devs {
					if dev.HasIP(nodeIP) {
						device = dev
						break
					}
				}
			}
		}
	}
	return device, watch
}
