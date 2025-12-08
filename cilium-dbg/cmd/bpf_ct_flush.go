// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/cilium/hive/shell"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/ctmap"
)

var direct bool

// bpfCtFlushCmd represents the bpf_ct_flush command
var bpfCtFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Flush all connection tracking entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		if direct {
			common.RequireRootPrivilege("cilium bpf ct flush")
			return flushCtBPFMap()
		}

		cfg := hive.DefaultShellConfig
		if err := cfg.Parse(cmd.Flags()); err != nil {
			return err
		}
		return shell.ShellExchange(cfg, os.Stdout, "ct/flush")
	},
}

func init() {
	bpfCtFlushCmd.Flags().BoolVarP(&direct, "direct", "d", false, "Directly flushing the CT BPF map (without Agent)")
	BPFCtCmd.AddCommand(bpfCtFlushCmd)
	hive.DefaultShellConfig.Flags(bpfCtFlushCmd.Flags())
}

func flushCtBPFMap() error {
	ipv4, ipv6 := getIpEnableStatuses()
	maps := ctmap.Maps(ipv4, ipv6)

	for _, m := range maps {
		path, err := ctmap.OpenCTMap(m)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Unable to open %s: %s. Skipping.\n", path, err)
				continue
			}
			return fmt.Errorf("unable to open %s: %w", path, err)
		}
		defer m.Close()

		if err := m.ClearAll(); err != nil {
			return fmt.Errorf("unable to clear %s: %w", path, err)
		}

		fmt.Printf("Flushed all entries from %s\n", path)
	}
	return nil
}
