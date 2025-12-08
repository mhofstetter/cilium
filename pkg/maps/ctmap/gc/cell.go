// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"fmt"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/maps/ctmap"
)

var Cell = cell.Module(
	"ct-nat-map-gc",
	"Garbage collection of CT and NAT maps",

	cell.Provide(
		// Provide the interface uses to start the GC logic. This hack
		// should be removed once all dependencies have been modularized,
		// and we can start the GC through a Start hook.
		func(gc *GC) ctmap.GCRunner { return gc },
	),
	// Provide the 'gc/' script commands for debugging and testing.
	cell.Provide(scriptCommands),

	cell.ProvidePrivate(
		newGC,

		// Register the signal handler for CT and NAT fill-up signals.
		newSignalHandler,
		// Provide the reduced interface used by the GC logic.
		func(mgr endpointmanager.EndpointManager) EndpointManager { return mgr },
	),
	cell.Config(config{
		ConntrackGCInterval:    0,
		ConntrackGCMaxInterval: 0,
	}),
)

func scriptCommands(gc *GC) hive.ScriptCmdsOut {
	cmds := map[string]script.Cmd{
		"ct/flush": ctFlush(gc),
	}

	return hive.NewScriptCmds(cmds)
}

func ctFlush(gc *GC) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Flush all connection tracking BPF maps",
			Args:    "",
			Detail:  []string{},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout string, stderr string, err error) {
				deleted := gc.flush()
				return fmt.Sprintf("Flushed %d entries from connection tracking maps", deleted), "", nil
			}, nil
		},
	)
}
