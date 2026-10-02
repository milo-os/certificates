// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	"sigs.k8s.io/multicluster-runtime/pkg/multicluster"
	mcclusters "sigs.k8s.io/multicluster-runtime/providers/clusters"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	serviceNamespace = "certificates-system"
	http01Issuer     = "letsencrypt-http01"
	dns01Issuer      = "letsencrypt-dns01"
	delegationZone   = "acme-dns.example.net"
	projectA         = "project-a"
	projectB         = "project-b"
)

var (
	cfg        *rest.Config
	k8sClient  client.Client
	k8sClientB client.Client
	testEnv    *envtest.Environment
	testEnvB   *envtest.Environment
	ctx        context.Context
	cancel     context.CancelFunc
	scheme     = runtime.NewScheme()
	resolver   = &fakeResolver{records: map[string]string{}, transient: map[string]bool{}}
	mcMgr      mcmanager.Manager
)

type fakeResolver struct {
	mu        sync.Mutex
	records   map[string]string
	transient map[string]bool
}

func (f *fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	host = strings.TrimSuffix(host, ".")
	if f.transient[host] {
		return "", &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
	}
	if target, ok := f.records[host]; ok {
		return target + ".", nil
	}
	return "", &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f *fakeResolver) set(host, target string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[host] = target
	delete(f.transient, host)
}

func (f *fakeResolver) remove(host string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.records, host)
	delete(f.transient, host)
}

func (f *fakeResolver) fail(host string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.transient[host] = true
}

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())
	SetDefaultEventuallyTimeout(15 * time.Second)
	SetDefaultEventuallyPollingInterval(100 * time.Millisecond)

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(certificatesv1alpha1.AddToScheme(scheme))
	utilruntime.Must(cmv1.AddToScheme(scheme))
	utilruntime.Must(acmev1.AddToScheme(scheme))

	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "base", "crd", "bases"),
			filepath.Join("testdata", "crds"),
		},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())

	Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: serviceNamespace}})).To(Succeed())

	testEnvB = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "base", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfgB, err := testEnvB.Start()
	Expect(err).NotTo(HaveOccurred())
	k8sClientB, err = client.New(cfgB, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())

	provider := mcclusters.New()
	for name, c := range map[string]*rest.Config{projectA: cfg, projectB: cfgB} {
		cl, err := cluster.New(c, func(o *cluster.Options) { o.Scheme = scheme })
		Expect(err).NotTo(HaveOccurred())
		Expect(provider.Add(ctx, multicluster.ClusterName(name), cl)).To(Succeed())
	}

	ns := map[string]cache.Config{serviceNamespace: {}}
	mcMgr, err = mcmanager.New(cfg, provider, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}:    {Namespaces: ns},
			&corev1.ConfigMap{}: {Namespaces: ns},
			&cmv1.Certificate{}: {Namespaces: ns},
			&acmev1.Order{}:     {Namespaces: ns},
			&acmev1.Challenge{}: {Namespaces: ns},
		}},
	})
	Expect(err).NotTo(HaveOccurred())

	Expect((&TLSCertificateReconciler{
		CertificateNamespace:      serviceNamespace,
		HTTP01ClusterIssuer:       http01Issuer,
		DNS01ClusterIssuer:        dns01Issuer,
		DNS01DelegationZone:       delegationZone,
		DeniedDomainSuffixes:      []string{"datumproxy.net"},
		MaxConcurrentReconciles:   2,
		Resolver:                  resolver,
		DelegationRecheckInterval: 200 * time.Millisecond,
		DelegatedRecheckInterval:  200 * time.Millisecond,
		SuspendAfterFailures:      3,
		SuspendAfter:              2 * time.Second,
	}).SetupWithManager(mcMgr)).To(Succeed())

	go func() {
		defer GinkgoRecover()
		Expect(mcMgr.Start(ctx)).To(Succeed())
	}()
})

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	Expect(testEnv.Stop()).To(Succeed())
	Expect(testEnvB.Stop()).To(Succeed())
})
