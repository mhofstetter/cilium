// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import "context"

type PortAllocator interface {
	AllocateProxyPort(name string, ingress, localOnly bool) (uint16, error)
	AckProxyPort(ctx context.Context, name string) error
	ReleaseProxyPort(name string) error
}
