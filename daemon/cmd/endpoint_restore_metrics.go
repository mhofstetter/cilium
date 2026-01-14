// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	metricsSubsystem = "endpoint_restoration"
)

type endpointRestoreMetrics struct {
	Endpoints                               metric.Vec[metric.Gauge]
	ReadOldEndpointsFromDiskDuration        metric.Gauge
	RestoreOldEndpointsDuration             metric.Gauge
	PrepareRegenerateOldEndpointsDuration   metric.Gauge
	RegenerateRestoredEndpointsDuration     metric.Gauge
	InitialEndpointPoliciesComputedDuration metric.Gauge
}

func newEndpointRestoreMetrics() *endpointRestoreMetrics {
	return &endpointRestoreMetrics{
		Endpoints: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: metricsSubsystem,
			Name:      "endpoints",
			Help:      "Number of restored endpoints labelled by phase and outcome",
		}, []string{"phase", "outcome"}),
		ReadOldEndpointsFromDiskDuration: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: metricsSubsystem,
			Name:      "read_old_endpoints_from_disk_duration_seconds",
			Help:      "Duration to read old endpoints from disk in seconds",
		}),
		RestoreOldEndpointsDuration: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: metricsSubsystem,
			Name:      "restore_old_endpoints_duration_seconds",
			Help:      "Duration to restore (validate and re-allocate IP) old endpoints in seconds",
		}),
		PrepareRegenerateOldEndpointsDuration: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: metricsSubsystem,
			Name:      "prepare_regenerate_restored_endpoints_duration_seconds",
			Help:      "Duration to prepare the regeneration of restored endpoints in seconds",
		}),
		RegenerateRestoredEndpointsDuration: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: metricsSubsystem,
			Name:      "regenerate_restored_endpoints_duration_seconds",
			Help:      "Duration to regenerate restored endpoints in seconds",
		}),
		InitialEndpointPoliciesComputedDuration: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: metricsSubsystem,
			Name:      "initial_endpoint_policies_computed_duration_seconds",
			Help:      "Duration until the initial endpoint policy for all restored endpoints is computed in seconds",
		}),
	}
}
