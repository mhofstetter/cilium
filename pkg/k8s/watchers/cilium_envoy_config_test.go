// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"encoding/json"
	"testing"

	. "github.com/cilium/checkmate"
	_ "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_http "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/envoy"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

var envoySpec = []byte(`apiVersion: cilium.io/v2
kind: CiliumClusterwideEnvoyConfig
metadata:
  name: envoy-prometheus-metrics-listener
spec:
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: envoy-prometheus-metrics-listener
    address:
      socket_address:
        address: "::"
        ipv4_compat: true
        port_value: 10000
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: envoy-prometheus-metrics-listener
          route_config:
            virtual_hosts:
            - name: "prometheus_metrics_route"
              domains: ["*"]
              routes:
              - match:
                  path: "/metrics"
                route:
                  cluster: "/envoy-admin"
                  prefix_rewrite: "/stats/prometheus"
          use_remote_address: true
          skip_xff_append: true
          http_filters:
          - name: envoy.filters.http.router
`)

func (s *K8sWatcherSuite) TestParseEnvoySpec(c *C) {
	jsonBytes, err := yaml.YAMLToJSON(envoySpec)
	c.Assert(err, IsNil)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	c.Assert(err, IsNil)
	c.Assert(cec.Spec.Resources, HasLen, 1)
	c.Assert(cec.Spec.Resources[0].TypeUrl, Equals, "type.googleapis.com/envoy.config.listener.v3.Listener")
	c.Assert(useOriginalSourceAddress(&cec.ObjectMeta), Equals, true)

	resources, err := envoy.ParseResources("", "name", cec.Spec.Resources, true, nil, len(cec.Spec.Services) > 0, useOriginalSourceAddress(&cec.ObjectMeta), false)
	c.Assert(err, IsNil)
	c.Assert(resources.Listeners, HasLen, 1)
	c.Assert(resources.Listeners[0].Address.GetSocketAddress().GetPortValue(), Equals, uint32(10000))
	c.Assert(resources.Listeners[0].FilterChains, HasLen, 1)
	c.Assert(resources.Listeners[0].Name, Equals, "/name/envoy-prometheus-metrics-listener")
	chain := resources.Listeners[0].FilterChains[0]
	c.Assert(chain.Filters, HasLen, 1)
	c.Assert(chain.Filters[0].Name, Equals, "envoy.filters.network.http_connection_manager")
	message, err := chain.Filters[0].GetTypedConfig().UnmarshalNew()
	c.Assert(err, IsNil)
	c.Assert(message, Not(IsNil))
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	c.Assert(ok, Equals, true)
	c.Assert(hcm, Not(IsNil))
	rc := hcm.GetRouteConfig()
	c.Assert(rc, Not(IsNil))
	vh := rc.VirtualHosts
	c.Assert(vh, HasLen, 1)
	c.Assert(vh[0].Name, Equals, "/name/prometheus_metrics_route")
	c.Assert(vh[0].Routes, HasLen, 1)
	c.Assert(vh[0].Routes[0].Match.GetPath(), Equals, "/metrics")
	c.Assert(vh[0].Routes[0].GetRoute().GetCluster(), Equals, "/envoy-admin")
	c.Assert(vh[0].Routes[0].GetRoute().GetPrefixRewrite(), Equals, "/stats/prometheus")
	c.Assert(hcm.HttpFilters, HasLen, 1)
	c.Assert(hcm.HttpFilters[0].Name, Equals, "envoy.filters.http.router")
}

func (s *K8sWatcherSuite) TestIsCiliumIngress(c *C) {
	// Non-ingress CEC
	jsonBytes, err := yaml.YAMLToJSON([]byte(`apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: envoy-prometheus-metrics-listener
spec:
  resources:
`))
	c.Assert(err, IsNil)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	c.Assert(err, IsNil)
	c.Assert(useOriginalSourceAddress(&cec.ObjectMeta), Equals, true)

	// Gateway API CCEC
	jsonBytes, err = yaml.YAMLToJSON([]byte(`apiVersion: cilium.io/v2
kind: CiliumClusterwideEnvoyConfig
metadata:
  name: cilium-gateway-all-namespaces
  ownerReferences:
  - apiVersion: gateway.networking.k8s.io/v1beta1
    kind: Gateway
    name: all-namespaces
    uid: bf4481cd-5d34-4880-93ec-76ddb34ab8a0
spec:
  resources:
`))
	c.Assert(err, IsNil)
	ccec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, ccec)
	c.Assert(err, IsNil)
	c.Assert(useOriginalSourceAddress(&ccec.ObjectMeta), Equals, false)

	// Ingress CEC
	jsonBytes, err = yaml.YAMLToJSON([]byte(`apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: cilium-ingress
  namespace: default
  ownerReferences:
  - apiVersion: networking.k8s.io/v1
    kind: Ingress
    name: basic-ingress
    namespace: default
spec:
  resources:
`))
	c.Assert(err, IsNil)
	cec = &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	c.Assert(err, IsNil)
	c.Assert(useOriginalSourceAddress(&cec.ObjectMeta), Equals, false)

	// CCEC with unknown owner kind
	jsonBytes, err = yaml.YAMLToJSON([]byte(`apiVersion: cilium.io/v2
kind: CiliumClusterwideEnvoyConfig
metadata:
  name: cilium-ingress
  ownerReferences:
  - apiVersion: example.io/v1
    kind: Monitoring
    name: test-monitor
spec:
  resources:
`))
	c.Assert(err, IsNil)
	ccec = &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, ccec)
	c.Assert(err, IsNil)
	c.Assert(useOriginalSourceAddress(&ccec.ObjectMeta), Equals, true)
}

func Test_filterServiceBackends(t *testing.T) {
	t.Run("filter by port number", func(t *testing.T) {
		svc := &loadbalancer.SVC{
			Frontend: loadbalancer.L3n4AddrID{
				L3n4Addr: loadbalancer.L3n4Addr{
					L4Addr: loadbalancer.L4Addr{
						Port: 8080,
					},
				},
			},
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "http",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 3000,
						},
					},
				},
			},
		}

		t.Run("all ports are allowed", func(t *testing.T) {
			backends := filterServiceBackends(svc, nil)
			assert.Len(t, backends, 1)
			assert.Len(t, backends["*"], 1)
		})
		t.Run("only http port", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"8080"})
			assert.Len(t, backends, 1)
			assert.Len(t, backends["8080"], 1)
		})
		t.Run("no match", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"8000"})
			assert.Len(t, backends, 0)
		})
	})

	t.Run("filter by port named", func(t *testing.T) {
		svc := &loadbalancer.SVC{
			Frontend: loadbalancer.L3n4AddrID{
				L3n4Addr: loadbalancer.L3n4Addr{
					L4Addr: loadbalancer.L4Addr{
						Port: 8000,
					},
				},
			},
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "http",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8080,
						},
					},
				},
				{
					FEPortName: "https",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8443,
						},
					},
				},
				{
					FEPortName: "metrics",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8081,
						},
					},
				},
			},
		}

		t.Run("all ports are allowed", func(t *testing.T) {
			backends := filterServiceBackends(svc, nil)
			assert.Len(t, backends, 1)
			assert.Len(t, backends["*"], 3)
		})
		t.Run("only http named port", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"http"})
			assert.Len(t, backends, 1)
			assert.Len(t, backends["http"], 1)
		})
		t.Run("multiple named ports", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"http", "metrics"})
			assert.Len(t, backends, 2)

			assert.Len(t, backends["http"], 1)
			assert.Equal(t, (int)(backends["http"][0].Port), 8080)

			assert.Len(t, backends["metrics"], 1)
			assert.Equal(t, (int)(backends["metrics"][0].Port), 8081)
		})
	})

	t.Run("filter with preferred backend", func(t *testing.T) {
		svc := &loadbalancer.SVC{
			Frontend: loadbalancer.L3n4AddrID{
				L3n4Addr: loadbalancer.L3n4Addr{
					L4Addr: loadbalancer.L4Addr{
						Port: 8000,
					},
				},
			},
			Backends: []*loadbalancer.Backend{
				{
					FEPortName: "http",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8080,
						},
					},
					Preferred: loadbalancer.Preferred(true),
				},
				{
					FEPortName: "http",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8081,
						},
					},
				},
				{
					FEPortName: "https",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 443,
						},
					},
				},
				{
					FEPortName: "80",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8080,
						},
					},
					Preferred: loadbalancer.Preferred(true),
				},
				{
					FEPortName: "80",
					L3n4Addr: loadbalancer.L3n4Addr{
						L4Addr: loadbalancer.L4Addr{
							Port: 8081,
						},
					},
				},
			},
		}

		t.Run("all ports are allowed", func(t *testing.T) {
			backends := filterServiceBackends(svc, nil)
			assert.Len(t, backends, 1)
			assert.Len(t, backends["*"], 2)
		})

		t.Run("only named ports", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"http"})
			assert.Len(t, backends, 1)
			assert.Len(t, backends["http"], 1)
		})
		t.Run("multiple named ports", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"http", "https"})
			assert.Len(t, backends, 1)

			assert.Len(t, backends["http"], 1)
			assert.Equal(t, (int)(backends["http"][0].Port), 8080)
		})

		t.Run("only port number", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"80"})
			assert.Len(t, backends, 1)

			assert.Len(t, backends["80"], 1)
			assert.Equal(t, (int)(backends["80"][0].Port), 8080)
		})
	})
}
