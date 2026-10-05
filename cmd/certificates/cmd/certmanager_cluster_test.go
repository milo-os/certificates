// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	mcsingle "sigs.k8s.io/multicluster-runtime/providers/single"
)

func TestNewCertManagerClusterWiring(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "internal", "controller", "testdata", "crds")},
		ErrorIfCRDPathMissing: true,
	}
	cmCfg, err := cmEnv.Start()
	if err != nil {
		t.Fatalf("starting cert-manager API server: %v", err)
	}
	defer func() { _ = cmEnv.Stop() }()

	localEnv := &envtest.Environment{}
	localCfg, err := localEnv.Start()
	if err != nil {
		t.Fatalf("starting local API server: %v", err)
	}
	defer func() { _ = localEnv.Stop() }()

	user, err := cmEnv.AddUser(envtest.User{Name: "certificates", Groups: []string{"system:masters"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	kubeconfig, err := user.KubeConfig()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, kubeconfig, 0o600); err != nil {
		t.Fatal(err)
	}

	const namespace = "certificates-system"
	if _, err := newCertManagerCluster(ctx, path, namespace); err == nil {
		t.Fatal("expected startup to fail while the namespace is missing on the cert-manager cluster")
	}

	direct, err := client.New(cmCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	if err := direct.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatal(err)
	}
	certManager, err := newCertManagerCluster(ctx, path, namespace)
	if err != nil || certManager == nil {
		t.Fatalf("expected a cert-manager cluster, got %v (err %v)", certManager, err)
	}

	local, err := cluster.New(localCfg, func(o *cluster.Options) { o.Scheme = scheme })
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := mcmanager.New(localCfg, mcsingle.New("single", local), ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Cache:   cache.Options{ByObject: localCacheObjects(namespace, true)},
	})
	if err != nil {
		t.Fatalf("local manager must start without cert-manager CRDs: %v", err)
	}
	if err := mgr.GetLocalManager().Add(certManager); err != nil {
		t.Fatal(err)
	}
	go func() { _ = mgr.Start(ctx) }()

	cert := &cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "probe"},
		Spec: cmv1.CertificateSpec{
			SecretName: "probe",
			DNSNames:   []string{"probe.example.com"},
			IssuerRef:  cmmeta.ObjectReference{Name: "issuer", Kind: cmv1.ClusterIssuerKind},
		},
	}
	if err := direct.Create(ctx, cert); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		err := certManager.GetClient().Get(ctx, client.ObjectKeyFromObject(cert), &cmv1.Certificate{})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cert-manager cluster cache never served the Certificate: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
