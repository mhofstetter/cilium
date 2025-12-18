package types

import "github.com/cilium/hive/cell"

// DevicesRequiredConfig is implemented by components that need a direct routing device.
// Components should register with Hive value groups by using DevicesRequiredConfigOut.
type DevicesRequiredConfig interface {
	// DevicesRequired should return true if a direct routing device is required.
	DevicesRequired() bool
}

type DevicesRequiredConfigOut struct {
	cell.Out

	Config DevicesRequiredConfig `group:"devicesRequired"`
}
