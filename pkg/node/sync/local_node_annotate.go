// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/pkg/annotation"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type localNodeAnnotaterParams struct {
	cell.In

	Config         config
	Logger         *slog.Logger
	JobGroup       job.Group
	Clientset      k8sClient.Clientset
	LocalNodeStore *node.LocalNodeStore
}

type localNodeAnnotater struct {
	logger         *slog.Logger
	k8sClient      kubernetes.Interface
	localNodeStore *node.LocalNodeStore
}

func registerLocalNodeAnnotator(params localNodeAnnotaterParams) {
	if !params.Clientset.IsEnabled() || !params.Config.AnnotateK8sNode {
		params.Logger.Debug("Annotating k8s node is disabled")
		return
	}

	annotater := &localNodeAnnotater{
		logger:         params.Logger,
		k8sClient:      params.Clientset,
		localNodeStore: params.LocalNodeStore,
	}

	retryObservable := stream.Retry(params.LocalNodeStore, stream.LimitRetries(stream.AlwaysRetry, 5))
	params.JobGroup.Add(job.Observer("annotate-k8s-node", annotater.annotate, retryObservable))
}

// Annotate writes v4 and v6 CIDRs and health IPs in the given k8s node name.
func (r *localNodeAnnotater) annotate(ctx context.Context, n node.LocalNode) error {
	r.logger.Info("Updating node annotations with node CIDRs",
		logfields.NodeName, n.Name,
		logfields.V4Prefix, n.IPv4AllocCIDR,
		logfields.V6Prefix, n.IPv6AllocCIDR,
		logfields.V4HealthIP, n.IPv4HealthIP,
		logfields.V6HealthIP, n.IPv6HealthIP,
		logfields.V4IngressIP, n.IPv4IngressIP,
		logfields.V6IngressIP, n.IPv6IngressIP,
		logfields.V4CiliumHostIP, n.GetCiliumInternalIP(false),
		logfields.V6CiliumHostIP, n.GetCiliumInternalIP(true),
		logfields.Key, n.EncryptionKey,
	)

	annotations := prepareNodeAnnotation(n.Node)

	if err := r.updateNodeAnnotation(n.Name, annotations); err != nil {
		return fmt.Errorf("failed to annotate k8s node with local node information: %w", err)
	}

	return nil
}

func prepareNodeAnnotation(node nodeTypes.Node) map[string]string {
	annotationMap := map[string]fmt.Stringer{
		annotation.V4CIDRName:     node.IPv4AllocCIDR,
		annotation.V6CIDRName:     node.IPv6AllocCIDR,
		annotation.V4HealthName:   node.IPv4HealthIP,
		annotation.V6HealthName:   node.IPv6HealthIP,
		annotation.V4IngressName:  node.IPv4IngressIP,
		annotation.V6IngressName:  node.IPv6IngressIP,
		annotation.CiliumHostIP:   node.GetCiliumInternalIP(false),
		annotation.CiliumHostIPv6: node.GetCiliumInternalIP(true),
	}

	annotations := map[string]string{}
	for k, v := range annotationMap {
		if !reflect.ValueOf(v).IsNil() {
			annotations[k] = v.String()
		}
	}
	if node.EncryptionKey != 0 {
		annotations[annotation.CiliumEncryptionKey] = strconv.FormatUint(uint64(node.EncryptionKey), 10)
	}
	return annotations
}

func (r *localNodeAnnotater) updateNodeAnnotation(nodeName string, annotation map[string]string) error {
	if len(annotation) == 0 {
		return nil
	}

	raw, err := json.Marshal(annotation)
	if err != nil {
		return err
	}
	patch := fmt.Appendf(nil, `{"metadata":{"annotations":%s}}`, raw)

	_, err = r.k8sClient.CoreV1().Nodes().Patch(context.TODO(), nodeName, k8sTypes.StrategicMergePatchType, patch, metav1.PatchOptions{}, "status")

	return err
}
