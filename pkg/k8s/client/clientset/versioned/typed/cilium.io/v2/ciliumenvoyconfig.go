// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package v2

import (
	"context"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// CiliumEnvoyConfigsGetter has a method to return a CiliumEnvoyConfigInterface.
// A group's client should implement this interface.
type CiliumEnvoyConfigsGetter interface {
	CiliumEnvoyConfigs(namespace string) CiliumEnvoyConfigInterface
}

// CiliumEnvoyConfigInterface has methods to work with CiliumEnvoyConfig resources.
type CiliumEnvoyConfigInterface interface {
	Create(ctx context.Context, ciliumEnvoyConfig *v2.CiliumEnvoyConfig, opts v1.CreateOptions) (*v2.CiliumEnvoyConfig, error)
	Update(ctx context.Context, ciliumEnvoyConfig *v2.CiliumEnvoyConfig, opts v1.UpdateOptions) (*v2.CiliumEnvoyConfig, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v2.CiliumEnvoyConfig, error)
	List(ctx context.Context, opts v1.ListOptions) (*v2.CiliumEnvoyConfigList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2.CiliumEnvoyConfig, err error)
	CiliumEnvoyConfigExpansion
}

// ciliumEnvoyConfigs implements CiliumEnvoyConfigInterface
type ciliumEnvoyConfigs struct {
	*gentype.ClientWithList[*v2.CiliumEnvoyConfig, *v2.CiliumEnvoyConfigList]
}

// newCiliumEnvoyConfigs returns a CiliumEnvoyConfigs
func newCiliumEnvoyConfigs(c *CiliumV2Client, namespace string) *ciliumEnvoyConfigs {
	return &ciliumEnvoyConfigs{
		gentype.NewClientWithList[*v2.CiliumEnvoyConfig, *v2.CiliumEnvoyConfigList](
			"ciliumenvoyconfigs",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *v2.CiliumEnvoyConfig { return &v2.CiliumEnvoyConfig{} },
			func() *v2.CiliumEnvoyConfigList { return &v2.CiliumEnvoyConfigList{} }),
	}
}
