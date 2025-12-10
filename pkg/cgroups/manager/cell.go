// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

// Cell provides access to the cgroup manager.
var Cell = cell.Module(
	"cgroup-manager",
	"CGroup Manager",

	cell.Provide(newCGroupManager),
	cell.Provide(newGetCgroupDumpMetadataRestApiHandler),
)

type cgroupManagerParams struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group

	AgentConfigPromise promise.Promise[*option.DaemonConfig]
}

func newCGroupManager(params cgroupManagerParams) CGroupManager {
	pathProvider, err := getCgroupPathProvider()
	if err != nil {
		params.Logger.
			Info(
				"Failed to setup socket load-balancing tracing with Hubble. See the kubeproxy-free guide for more details.",
				logfields.Error, err,
			)

		return &noopCGroupManager{}
	}

	cm := newManager(params.Logger, cgroupImpl{}, pathProvider, podEventsChannelSize)

	params.JobGroup.Add(job.OneShot("process-pod-events", func(ctx context.Context, health cell.Health) error {
		dc, err := params.AgentConfigPromise.Await(ctx)
		if err != nil {
			return fmt.Errorf("failed to wait for daemon promise: %w", err)
		}

		if !dc.EnableSocketLBTracing {
			return nil
		}

		params.Logger.Info("Cgroup metadata manager is enabled")

		cm.processPodEvents(ctx)
		return nil
	}))

	return cm
}
