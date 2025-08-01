// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"sync"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func cidResourceKey(cidName string) resource.Key {
	return resource.Key{Name: cidName}
}

type CIDItem struct {
	key resource.Key
}

func (c CIDItem) Key() resource.Key {
	return c.key
}

func (c CIDItem) Reconcile(reconciler *reconciler) error {
	return reconciler.reconcileCID(c.key)
}

func (c CIDItem) Meter(enqueuedLatency float64, processingLatency float64, isErr bool, metrics *Metrics) {
	metrics.meterLatency(LabelValueCID, enqueuedLatency, processingLatency)
	metrics.markEvent(LabelValueCID, isErr)
}

func (c *Controller) processCiliumIdentityEvents(ctx context.Context, wg *sync.WaitGroup) error {
	for event := range c.ciliumIdentity.Events(ctx) {
		if event.Kind == resource.Sync {
			wg.Done()
		}

		if event.Kind == resource.Upsert || event.Kind == resource.Delete {
			c.logger.DebugContext(ctx,
				"Got CID event",
				logfields.Type, event.Kind,
				logfields.CIDName, event.Key,
			)
			c.enqueueReconciliation(CIDItem{cidResourceKey(event.Object.Name)}, 0)
		}
		event.Done(nil)
	}
	return nil
}
