// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"io"
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
)

func Test_k8sToEnvoySecret(t *testing.T) {
	envoySecret := k8sToEnvoySecret(&slim_corev1.Secret{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "dummy-secret",
			Namespace: "dummy-namespace",
		},
		Data: map[string]slim_corev1.Bytes{
			"tls.crt": []byte{1, 2, 3},
			"tls.key": []byte{4, 5, 6},
		},
		Type: "kubernetes.io/tls",
	})

	require.Equal(t, "dummy-namespace/dummy-secret", envoySecret.Name)
	require.Equal(t, []byte{1, 2, 3}, envoySecret.GetTlsCertificate().GetCertificateChain().GetInlineBytes())
	require.Equal(t, []byte{4, 5, 6}, envoySecret.GetTlsCertificate().GetPrivateKey().GetInlineBytes())
}

func TestHandleSecretEvent(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	xdsServer := &fakeXdsServer{}

	syncer := newSecretSyncer(logger, xdsServer)

	doneCalled := false
	var doneError error

	doneFunc := func(err error) {
		doneCalled = true
		doneError = err
	}

	// init
	assert.Empty(t, syncer.secrets)

	// upsert of unknown secret1
	secret1 := testSecret("test1", "content")
	err := syncer.handleSecretEvent(context.Background(), testEvent(secret1, resource.Upsert, doneFunc))
	assert.NoError(t, err)

	assert.Len(t, syncer.secrets, 1)
	assert.Equal(t, secret1, syncer.secrets[resource.NewKey(secret1)])

	assert.True(t, doneCalled)
	assert.NoError(t, doneError)

	assert.Equal(t, 1, xdsServer.nrOfUpserts, "Secret should be upserted")
	assert.Equal(t, 0, xdsServer.nrOfUpdates, "Secret should't be updated")
	assert.Equal(t, 0, xdsServer.nrOfDeletions, "Secret should't be deleted")

	// sync
	xdsServer.Reset()
	doneCalled = false

	secret1 = testSecret("test1", "content")
	err = syncer.handleSecretEvent(context.Background(), testEvent(secret1, resource.Sync, doneFunc))
	assert.NoError(t, err)

	assert.Len(t, syncer.secrets, 1)
	assert.Equal(t, secret1, syncer.secrets[resource.NewKey(secret1)])

	assert.True(t, doneCalled)
	assert.NoError(t, doneError)

	assert.Equal(t, 0, xdsServer.nrOfUpserts, "Secret shouldn't be upserted")
	assert.Equal(t, 0, xdsServer.nrOfUpdates, "Secret should't be updated")
	assert.Equal(t, 0, xdsServer.nrOfDeletions, "Secret should't be deleted")

	// upsert of existing secret without changes
	xdsServer.Reset()
	doneCalled = false

	secret1 = testSecret("test1", "content")
	err = syncer.handleSecretEvent(context.Background(), testEvent(secret1, resource.Upsert, doneFunc))
	assert.NoError(t, err)

	assert.Len(t, syncer.secrets, 1)
	assert.Equal(t, secret1, syncer.secrets[resource.NewKey(secret1)])

	assert.True(t, doneCalled)
	assert.NoError(t, doneError)

	assert.Equal(t, 0, xdsServer.nrOfUpserts, "Secret shouldn't be upserted")
	assert.Equal(t, 0, xdsServer.nrOfUpdates, "Secret shouldn't be updated")
	assert.Equal(t, 0, xdsServer.nrOfDeletions, "Secret should't be deleted")

	// upsert of existing secret with changes
	xdsServer.Reset()
	doneCalled = false

	secret1 = testSecret("test1", "changed-content")
	err = syncer.handleSecretEvent(context.Background(), testEvent(secret1, resource.Upsert, doneFunc))
	assert.NoError(t, err)

	assert.Len(t, syncer.secrets, 1)
	assert.Equal(t, secret1, syncer.secrets[resource.NewKey(secret1)])

	assert.True(t, doneCalled)
	assert.NoError(t, doneError)

	assert.Equal(t, 1, xdsServer.nrOfUpserts, "Secret should be upserted")
	assert.Equal(t, 0, xdsServer.nrOfUpdates, "Secret shouldn't be updated")
	assert.Equal(t, 0, xdsServer.nrOfDeletions, "Secret should't be deleted")

	// upsert of additional secret
	xdsServer.Reset()
	doneCalled = false

	secret2 := testSecret("test2", "content")
	err = syncer.handleSecretEvent(context.Background(), testEvent(secret2, resource.Upsert, doneFunc))
	assert.NoError(t, err)

	assert.Len(t, syncer.secrets, 2)
	assert.Equal(t, secret1, syncer.secrets[resource.NewKey(secret1)])
	assert.Equal(t, secret2, syncer.secrets[resource.NewKey(secret2)])

	assert.True(t, doneCalled)
	assert.NoError(t, doneError)

	assert.Equal(t, 1, xdsServer.nrOfUpserts, "Secret should be upserted")
	assert.Equal(t, 0, xdsServer.nrOfUpdates, "Secret shouldn't be updated")
	assert.Equal(t, 0, xdsServer.nrOfDeletions, "Secret should't be deleted")

	// delete of existing secret
	xdsServer.Reset()
	doneCalled = false

	secret1 = testSecret("test1", "content")
	err = syncer.handleSecretEvent(context.Background(), testEvent(secret1, resource.Delete, doneFunc))
	assert.NoError(t, err)

	assert.Len(t, syncer.secrets, 1)
	assert.Equal(t, secret2, syncer.secrets[resource.NewKey(secret2)])

	assert.True(t, doneCalled)
	assert.NoError(t, doneError)

	assert.Equal(t, 0, xdsServer.nrOfUpserts, "Secret shouldn't be upserted")
	assert.Equal(t, 0, xdsServer.nrOfUpdates, "Secret shouldn't be updated")
	assert.Equal(t, 1, xdsServer.nrOfDeletions, "Secret should be deleted")

	// delete of unexisting secret
	xdsServer.Reset()
	doneCalled = false

	secret3 := testSecret("test3", "content")
	err = syncer.handleSecretEvent(context.Background(), testEvent(secret3, resource.Delete, doneFunc))
	assert.NoError(t, err)

	assert.Len(t, syncer.secrets, 1)
	assert.Equal(t, secret2, syncer.secrets[resource.NewKey(secret2)])

	assert.True(t, doneCalled)
	assert.NoError(t, doneError, "deletion of unknown secret shouldn't result in an error")

	assert.Equal(t, 0, xdsServer.nrOfUpserts, "Secret shouldn't be upserted")
	assert.Equal(t, 0, xdsServer.nrOfUpdates, "Secret shouldn't be updated")
	assert.Equal(t, 0, xdsServer.nrOfDeletions, "Secret shouldn't be deleted")
}

func testEvent(secret *slim_corev1.Secret, eventKind resource.EventKind, eventDone func(err error)) resource.Event[*slim_corev1.Secret] {
	event := resource.Event[*slim_corev1.Secret]{}
	event.Key = resource.NewKey(secret)
	event.Object = secret
	event.Kind = eventKind
	event.Done = eventDone

	return event
}

func testSecret(secretName string, data string) *slim_corev1.Secret {
	return &slim_corev1.Secret{
		ObjectMeta: slim_metav1.ObjectMeta{
			Namespace: "test",
			Name:      secretName,
		},
		Data: map[string]slim_corev1.Bytes{
			"tls.crt": []byte(data),
		},
		Type: "kubernetes.io/tls",
	}
}

type fakeXdsServer struct {
	nrOfDeletions int
	nrOfUpdates   int
	nrOfUpserts   int
}

var _ XDSServer = &fakeXdsServer{}

func (r *fakeXdsServer) Reset() {
	r.nrOfUpdates = 0
	r.nrOfUpserts = 0
	r.nrOfDeletions = 0
}

func (r *fakeXdsServer) UpdateEnvoyResources(ctx context.Context, old Resources, new Resources) error {
	r.nrOfUpdates++
	return nil
}

func (r *fakeXdsServer) DeleteEnvoyResources(ctx context.Context, resources Resources) error {
	r.nrOfDeletions++
	return nil
}

func (r *fakeXdsServer) UpsertEnvoyResources(ctx context.Context, resources Resources) error {
	r.nrOfUpserts++
	return nil
}

func (*fakeXdsServer) AddListener(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*fakeXdsServer) AddMetricsListener(port uint16, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*fakeXdsServer) GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error) {
	panic("unimplemented")
}

func (*fakeXdsServer) RemoveAllNetworkPolicies() {
	panic("unimplemented")
}

func (*fakeXdsServer) RemoveListener(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	panic("unimplemented")
}

func (*fakeXdsServer) RemoveNetworkPolicy(ep endpoint.EndpointInfoSource) {
	panic("unimplemented")
}

func (*fakeXdsServer) UpdateNetworkPolicy(ep endpoint.EndpointUpdater, vis *policy.VisibilityPolicy, policy *policy.L4Policy, ingressPolicyEnforced bool, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	panic("unimplemented")
}
