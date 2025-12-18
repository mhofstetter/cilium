// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kpr

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	datapathtablestypes "github.com/cilium/cilium/pkg/datapath/tables/types"
)

var Cell = cell.Module(
	"kube-proxy-replacement",
	"Provides KPR config",

	cell.Config(defaultFlags),
	cell.Provide(NewKPRConfig),
)

type KPRFlags struct {
	KubeProxyReplacement bool
	EnableSocketLB       bool `mapstructure:"bpf-lb-sock"`
}

var defaultFlags = KPRFlags{
	KubeProxyReplacement: false,
	EnableSocketLB:       false,
}

func (def KPRFlags) Flags(flags *pflag.FlagSet) {
	flags.Bool("kube-proxy-replacement", def.KubeProxyReplacement, "Enable kube-proxy replacement")

	flags.Bool("bpf-lb-sock", def.EnableSocketLB, "Enable socket-based LB for E/W traffic")
}

type KPRConfig struct {
	KubeProxyReplacement bool
	EnableSocketLB       bool
}

func (r *KPRConfig) DevicesRequired() bool {
	return r.KubeProxyReplacement
}

func NewKPRConfig(flags KPRFlags) (KPRConfig, datapathtablestypes.DevicesRequiredConfigOut, error) {
	//nolint:staticcheck
	cfg := KPRConfig{
		KubeProxyReplacement: flags.KubeProxyReplacement,
		EnableSocketLB:       flags.EnableSocketLB,
	}

	if flags.KubeProxyReplacement {
		cfg.EnableSocketLB = true
	}

	return cfg, datapathtablestypes.DevicesRequiredConfigOut{Config: &cfg}, nil
}
