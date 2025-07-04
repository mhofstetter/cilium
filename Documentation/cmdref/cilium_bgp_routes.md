<!-- This file was autogenerated via cilium cmdref, do not edit manually-->

## cilium bgp routes

Lists BGP routes

### Synopsis

Lists BGP routes from all nodes in the cluster

```
cilium bgp routes <available | advertised> <afi> <safi> [vrouter <asn>] [peer|neighbor <address>] [flags]
```

### Examples

```
  Get all IPv4 unicast routes available:
    cilium bgp routes available ipv4 unicast

  Get all IPv6 unicast routes available for a specific vrouter:
    cilium bgp routes available ipv6 unicast vrouter 65001

  Get IPv4 unicast routes advertised to a specific peer:
    cilium bgp routes advertised ipv4 unicast peer 10.0.0.1
```

### Options

```
      --agent-pod-selector string   Label on cilium-agent pods to select with (default "k8s-app=cilium")
  -h, --help                        help for routes
      --node string                 Node from which BGP routes will be fetched, omit to select all nodes
  -o, --output string               Output format. One of: json, summary (default "summary")
      --wait-duration duration      Maximum time to wait for result, default 1 minute (default 1m0s)
```

### Options inherited from parent commands

```
      --as string                  Username to impersonate for the operation. User could be a regular user or a service account in a namespace.
      --as-group stringArray       Group to impersonate for the operation, this flag can be repeated to specify multiple groups.
      --context string             Kubernetes configuration context
      --helm-release-name string   Helm release name (default "cilium")
      --kubeconfig string          Path to the kubeconfig file
  -n, --namespace string           Namespace Cilium is running in (default "kube-system")
```

### SEE ALSO

* [cilium bgp](cilium_bgp.md)	 - Access to BGP control plane

