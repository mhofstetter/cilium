// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sync

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

type localNodeAnnotater struct {
	Logger         *slog.Logger
	Clientset      k8sClient.Clientset
	LocalNodeStore *node.LocalNodeStore
}

type localNodeAnnotaterParams struct {
	cell.In

	Logger         *slog.Logger
	JobGroup       job.Group
	Clientset      k8sClient.Clientset
	LocalNodeStore *node.LocalNodeStore
}

func registerLocalNodeAnnotator(params localNodeAnnotaterParams) {
	if !params.Clientset.IsEnabled() || !option.Config.AnnotateK8sNode {
		params.Logger.Debug("Annotating k8s node is disabled")
		return
	}

	annotater := &localNodeAnnotater{
		Logger:         params.Logger,
		Clientset:      params.Clientset,
		LocalNodeStore: params.LocalNodeStore,
	}

	params.JobGroup.Add(job.Observer("annotate-k8s-node", annotater.annotate, params.LocalNodeStore))
}

func (r *localNodeAnnotater) annotate(ctx context.Context, n node.LocalNode) error {
	if _, err := k8s.AnnotateNode(r.Logger, r.Clientset, n.Node); err != nil {
		return fmt.Errorf("failed to annotate k8s node with local node information: %w", err)
	}

	return nil
}
