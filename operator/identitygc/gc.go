// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/workerpool"

	authIdentity "github.com/cilium/cilium/operator/auth/identity"
	"github.com/cilium/cilium/pkg/allocator"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	ciliumV2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
)

// params contains all the dependencies for the identity-gc.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle

	Clientset           k8sClient.Clientset
	KVStoreClient       kvstore.Client
	Identity            resource.Resource[*v2.CiliumIdentity]
	CiliumEndpoint      resource.Resource[*v2.CiliumEndpoint]
	CiliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice]
	AuthIdentityClient  authIdentity.Provider

	Cfg         Config
	SharedCfg   SharedConfig
	ClusterInfo cmtypes.ClusterInfo

	Metrics *Metrics
}

// GC represents the Cilium identities periodic GC.
type GC struct {
	logger *slog.Logger

	clientset           ciliumV2.CiliumIdentityInterface
	kvstoreClient       kvstore.Client
	identity            resource.Resource[*v2.CiliumIdentity]
	ciliumEndpoint      resource.Resource[*v2.CiliumEndpoint]
	ciliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice]
	authIdentityClient  authIdentity.Provider

	clusterInfo    cmtypes.ClusterInfo
	allocationMode string

	gcInterval       time.Duration
	heartbeatTimeout time.Duration
	gcRateInterval   time.Duration
	gcRateLimit      int64

	wp             *workerpool.WorkerPool
	heartbeatStore *heartbeatStore
	mgr            *controller.Manager

	// rateLimiter is meant to rate limit the number of
	// identities being GCed by the operator. See the documentation of
	// rate.Limiter to understand its difference than 'x/time/rate.Limiter'.
	//
	// With our rate.Limiter implementation Cilium will be able to handle bursts
	// of identities being garbage collected with the help of the functionality
	// provided by the 'policy-trigger-interval' in the cilium-agent. With the
	// policy-trigger even if we receive N identity changes over the interval
	// set, Cilium will only need to process all of them at once instead of
	// processing each one individually.
	rateLimiter *rate.Limiter

	allocator *allocator.Allocator

	metrics *Metrics
}

func registerGC(p params) {
	if !p.Clientset.IsEnabled() {
		return
	}

	gc := &GC{
		logger:              p.Logger,
		clientset:           p.Clientset.CiliumV2().CiliumIdentities(),
		kvstoreClient:       p.KVStoreClient,
		identity:            p.Identity,
		ciliumEndpoint:      p.CiliumEndpoint,
		ciliumEndpointSlice: p.CiliumEndpointSlice,
		authIdentityClient:  p.AuthIdentityClient,
		clusterInfo:         p.ClusterInfo,
		allocationMode:      p.SharedCfg.IdentityAllocationMode,
		gcInterval:          p.Cfg.Interval,
		heartbeatTimeout:    p.Cfg.HeartbeatTimeout,
		gcRateInterval:      p.Cfg.RateInterval,
		gcRateLimit:         p.Cfg.RateLimit,
		heartbeatStore: newHeartbeatStore(
			p.Cfg.HeartbeatTimeout,
			p.Logger,
		),
		rateLimiter: rate.NewLimiter(
			p.Cfg.RateInterval,
			p.Cfg.RateLimit,
		),
		metrics: p.Metrics,
	}
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			switch gc.allocationMode {
			case option.IdentityAllocationModeCRD:
				gc.wp = workerpool.New(1)
				return gc.startCRDModeGC(ctx)
			case option.IdentityAllocationModeKVstore:
				gc.wp = workerpool.New(1)
				return gc.startKVStoreModeGC(ctx)
			case option.IdentityAllocationModeDoubleWriteReadCRD, option.IdentityAllocationModeDoubleWriteReadKVstore:
				gc.wp = workerpool.New(2)
				err := gc.startCRDModeGC(ctx)
				if err != nil {
					return err
				}
				err = gc.startKVStoreModeGC(ctx)
				if err != nil {
					return err
				}
				return nil
			default:
				return fmt.Errorf("unknown Cilium identity allocation mode: %q", gc.allocationMode)
			}
		},
		OnStop: func(ctx cell.HookContext) error {
			if gc.allocationMode == option.IdentityAllocationModeCRD ||
				gc.allocationMode == option.IdentityAllocationModeDoubleWriteReadCRD ||
				gc.allocationMode == option.IdentityAllocationModeDoubleWriteReadKVstore {
				// CRD mode GC runs in an additional goroutine
				gc.mgr.RemoveAllAndWait()
			}
			gc.rateLimiter.Stop()
			gc.wp.Close()

			return nil
		},
	})
}
