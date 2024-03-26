// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

const (
	// ListenerTypeURL is the type URL of Listener resources.
	ListenerTypeURL = "type.googleapis.com/envoy.config.listener.v3.Listener"

	// RouteTypeURL is the type URL of HTTP Route resources.
	RouteTypeURL = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration"

	// ClusterTypeURL is the type URL of Cluster resources.
	ClusterTypeURL = "type.googleapis.com/envoy.config.cluster.v3.Cluster"

	// HttpConnectionManagerTypeURL is the type URL of HttpConnectionManager filter.
	HttpConnectionManagerTypeURL = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"

	// TCPProxyTypeURL is the type URL of TCPProxy filter.
	TCPProxyTypeURL = "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy"

	// EndpointTypeURL is the type URL of Endpoint resources.
	EndpointTypeURL = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment"

	// SecretTypeURL is the type URL of Endpoint resources.
	SecretTypeURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

	// NetworkPolicyTypeURL is the type URL of NetworkPolicy resources.
	NetworkPolicyTypeURL = "type.googleapis.com/cilium.NetworkPolicy"

	// HealthCheckSinkPipeTypeURL is the type URL of NetworkPolicyHosts resources.
	HealthCheckSinkPipeTypeURL = "type.googleapis.com/cilium.health_check.event_sink.pipe"

	// DownstreamTlsContextURL is the type URL of DownstreamTlsContext
	DownstreamTlsContextURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext"
)
