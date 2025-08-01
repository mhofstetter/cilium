// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/pkg/clustermesh/operator"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var Cell = cell.Module(
	"mcsapi",
	"Multi-Cluster Services API",
	cell.Invoke(registerMCSAPIController),
)

var ServiceExportSyncCell = cell.Module(
	"service-export-sync",
	"Synchronizes Kubernetes ServiceExports to KVStore",

	cell.Invoke(registerServiceExportSync),
)

type mcsAPIParams struct {
	cell.In

	ClusterMesh operator.ClusterMesh
	Cfg         operator.ClusterMeshConfig
	CfgMCSAPI   operator.MCSAPIConfig

	// ClusterInfo is the id/name of the local cluster.
	ClusterInfo types.ClusterInfo

	Clientset          k8sClient.Clientset
	CtrlRuntimeManager ctrlRuntime.Manager
	Scheme             *runtime.Scheme

	Logger   *slog.Logger
	JobGroup job.Group
}

var requiredGVK = []schema.GroupVersionKind{
	mcsapiv1alpha1.SchemeGroupVersion.WithKind("serviceimports"),
	mcsapiv1alpha1.SchemeGroupVersion.WithKind("serviceexports"),
}

func checkCRD(ctx context.Context, clientset k8sClient.Clientset, gvk schema.GroupVersionKind) error {
	if !clientset.IsEnabled() {
		return nil
	}

	crd, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, gvk.GroupKind().String(), metav1.GetOptions{})
	if err != nil {
		return err
	}

	found := false
	for _, v := range crd.Spec.Versions {
		if v.Name == gvk.Version {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("CRD %q does not have version %q", gvk.GroupKind().String(), gvk.Version)
	}

	return nil
}

func checkRequiredCRDs(ctx context.Context, clientset k8sClient.Clientset) error {
	var res error
	for _, gvk := range requiredGVK {
		if err := checkCRD(ctx, clientset, gvk); err != nil {
			res = errors.Join(res, err)
		}
	}
	return res
}

func registerMCSAPIController(params mcsAPIParams) error {
	if !params.Clientset.IsEnabled() || params.ClusterMesh == nil || !params.CfgMCSAPI.ClusterMeshEnableMCSAPI {
		return nil
	}

	params.Logger.Info(
		"Checking for required MCS-API resources",
		logfields.RequiredGVK, requiredGVK,
	)
	if err := checkRequiredCRDs(context.Background(), params.Clientset); err != nil {
		params.Logger.Error(
			"Required MCS-API resources are not found, please refer to docs for installation instructions",
			logfields.Error, err,
		)
		return err
	}
	if err := mcsapiv1alpha1.AddToScheme(params.Scheme); err != nil {
		return err
	}

	if err := newMCSAPIServiceReconciler(params.CtrlRuntimeManager, params.Logger).SetupWithManager(params.CtrlRuntimeManager); err != nil {
		return fmt.Errorf("Failed to register MCSAPIServiceReconciler: %w", err)
	}

	if err := newMCSAPIEndpointSliceMirrorReconciler(params.CtrlRuntimeManager, params.Logger, params.ClusterInfo.Name).SetupWithManager(params.CtrlRuntimeManager); err != nil {
		return fmt.Errorf("Failed to register MCSAPIEndpointSliceMirrorReconciler: %w", err)
	}

	params.Logger.Info("Multi-Cluster Services API support enabled")

	remoteClusterServiceSource := &remoteClusterServiceExportSource{Logger: params.Logger}
	params.ClusterMesh.RegisterClusterServiceExportUpdateHook(remoteClusterServiceSource.onClusterServiceExportEvent)
	params.ClusterMesh.RegisterClusterServiceExportDeleteHook(remoteClusterServiceSource.onClusterServiceExportEvent)
	svcImportReconciler := newMCSAPIServiceImportReconciler(
		params.CtrlRuntimeManager, params.Logger, params.ClusterInfo.Name,
		params.ClusterMesh.GlobalServiceExports(), remoteClusterServiceSource,
	)

	params.JobGroup.Add(job.OneShot("mcsapi-main", func(ctx context.Context, health cell.Health) error {
		params.Logger.Info("Bootstrap Multi-Cluster Services API support")

		if err := params.ClusterMesh.ServiceExportsSynced(ctx); err != nil {
			return nil // The parent context expired, and we are already terminating
		}

		if err := svcImportReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
			return fmt.Errorf("Failed to register mcsapicontrollers.ServiceImportReconciler: %w", err)
		}

		return nil
	}))
	return nil
}
