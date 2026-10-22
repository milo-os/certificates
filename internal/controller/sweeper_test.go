// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
)

type localOnlyManager struct {
	mcmanager.Manager
	local manager.Manager
}

func (m localOnlyManager) GetLocalManager() manager.Manager { return m.local }

type clientOnlyManager struct {
	manager.Manager
	client client.Client
}

func (m clientOnlyManager) GetClient() client.Client { return m.client }

func TestSweepContinuesPastFailedDelete(t *testing.T) {
	const namespace = "certs"
	scheme := runtime.NewScheme()
	if err := errors.Join(clientgoscheme.AddToScheme(scheme), cmv1.AddToScheme(scheme)); err != nil {
		t.Fatal(err)
	}
	orphan := func(name string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{UpstreamUIDLabel: "uid"},
		}}
	}
	failing := orphan("b")
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(orphan("a"), failing, orphan("c")).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if obj.GetName() == "b" {
					return errors.New("boom")
				}
				return cl.Delete(ctx, obj, opts...)
			},
		}).Build()

	clock := time.Now()
	sweeper := &OrphanSweeper{
		Manager:              localOnlyManager{local: clientOnlyManager{client: c}},
		CertificateNamespace: namespace,
		GracePeriod:          time.Minute,
		now:                  func() time.Time { return clock },
	}
	ctx := context.Background()

	if err := sweeper.Sweep(ctx); err != nil {
		t.Fatalf("first pass only records first-seen: %v", err)
	}
	clock = clock.Add(2 * time.Minute)
	if err := sweeper.Sweep(ctx); err == nil {
		t.Fatal("expected the failed delete to be returned")
	}

	for _, name := range []string{"a", "c"} {
		err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &corev1.Secret{})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("orphan %s was not deleted: %v", name, err)
		}
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(failing), &corev1.Secret{}); err != nil {
		t.Fatalf("failing orphan should remain: %v", err)
	}
	if _, ok := sweeper.missingSince["b"]; !ok {
		t.Fatal("failed orphan must stay tracked so the next pass retries it")
	}
	if len(sweeper.missingSince) != 1 {
		t.Fatalf("deleted orphans must be pruned, tracking %v", sweeper.missingSince)
	}
}
