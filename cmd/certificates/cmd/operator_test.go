// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/multicluster-runtime/pkg/multicluster"

	"go.miloapis.com/certificates/internal/config"
)

func TestDefaultFlagsRequireServiceIdentitiesWithWebhook(t *testing.T) {
	cmd := newOperatorCommand(BuildInfo{})
	if err := cmd.Flags().Parse(nil); err != nil {
		t.Fatal(err)
	}
	writers, _ := cmd.Flags().GetStringSlice("allowed-writer-identities")
	services, _ := cmd.Flags().GetStringSlice("service-identities")
	deleters, _ := cmd.Flags().GetStringSlice("allowed-deleter-identities")
	denied, _ := cmd.Flags().GetStringSlice("denied-domain-suffixes")
	f := issuanceFlags{
		certificateNamespace: "certificates-system",
		writerIdentities:     writers,
		serviceIdentities:    services,
		deleterIdentities:    deleters,
		deniedDomainSuffixes: denied,
	}

	if err := f.validateWebhook(true); err == nil {
		t.Fatal("expected default flags to be refused when the webhook is enabled")
	}
	if err := f.validateWebhook(false); err != nil {
		t.Fatalf("expected default flags to be accepted without the webhook, got %v", err)
	}
	f.serviceIdentities = []string{"system:control@certificates.miloapis.com"}
	if err := f.validateWebhook(true); err != nil {
		t.Fatalf("expected service identities to satisfy the webhook check, got %v", err)
	}

	if len(deleters) == 0 || deleters[0] != "system:control@platform.miloapis.com" {
		t.Errorf("default --allowed-deleter-identities must include Milo's controller manager, got %v", deleters)
	}

	for _, want := range []string{"datumproxy.net", "datum.net", "datum-staging.net", "datumdomains.net", "miloapis.com", "datumapis.com"} {
		found := false
		for _, d := range denied {
			found = found || d == want
		}
		if !found {
			t.Errorf("default --denied-domain-suffixes is missing %s", want)
		}
	}
}

func TestDNS01FlagsMustBeSetTogether(t *testing.T) {
	f := issuanceFlags{certificateNamespace: "certificates-system", dns01ClusterIssuer: "dns01"}
	if err := f.validate(); err == nil {
		t.Fatal("expected an error when the delegation zone is missing")
	}
	f.dns01DelegationZone = "acme-dns.example.net"
	if err := f.validate(); err != nil {
		t.Fatal(err)
	}
}

type stubReader struct {
	client.Reader
	err error
	got client.ObjectKey
	gvk schema.GroupVersionKind
}

func (r *stubReader) Get(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	r.got = key
	r.gvk = obj.GetObjectKind().GroupVersionKind()
	return r.err
}

func TestProjectChecker(t *testing.T) {
	gr := schema.GroupResource{Group: "resourcemanager.miloapis.com", Resource: "projects"}
	tests := []struct {
		name    string
		err     error
		exists  bool
		wantErr bool
	}{
		{name: "found", exists: true},
		{name: "not found", err: apierrors.NewNotFound(gr, "p")},
		{name: "timeout", err: apierrors.NewTimeoutError("slow", 1), exists: false, wantErr: true},
		{name: "forbidden", err: apierrors.NewForbidden(gr, "p", errors.New("denied")), exists: false, wantErr: true},
		{name: "context deadline", err: context.DeadlineExceeded, exists: false, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &stubReader{err: tt.err}
			exists, err := projectChecker(reader, false).ProjectExists(context.Background(), multicluster.ClusterName("p"))
			if exists != tt.exists || (err != nil) != tt.wantErr {
				t.Fatalf("got exists=%v err=%v, want exists=%v wantErr=%v", exists, err, tt.exists, tt.wantErr)
			}
			if reader.got != (client.ObjectKey{Name: "p"}) || reader.gvk.Kind != "Project" {
				t.Fatalf("looked up %v %v", reader.gvk, reader.got)
			}
		})
	}

	reader := &stubReader{}
	if _, err := projectChecker(reader, true).ProjectExists(context.Background(), "p"); err != nil || reader.gvk.Kind != "ProjectControlPlane" {
		t.Fatalf("internal discovery looked up %v (err %v)", reader.gvk, err)
	}
}

func TestCertManagerClusterUnsetKeepsLocalCluster(t *testing.T) {
	cl, err := newCertManagerCluster(context.Background(), "", "certificates-system")
	if err != nil || cl != nil {
		t.Fatalf("expected no separate cluster without a kubeconfig, got %v (err %v)", cl, err)
	}

	objects := localCacheObjects("certificates-system", false)
	for _, obj := range []client.Object{&corev1.ConfigMap{}, &corev1.Secret{}, &cmv1.Certificate{}, &acmev1.Order{}, &acmev1.Challenge{}} {
		if !cachesType(objects, obj, "certificates-system") {
			t.Errorf("local cache must scope %T to the certificate namespace", obj)
		}
	}
}

func TestCertManagerClusterSetMovesIssuanceOffTheLocalCache(t *testing.T) {
	objects := localCacheObjects("certificates-system", true)
	if !cachesType(objects, &corev1.ConfigMap{}, "certificates-system") {
		t.Error("delegation anchors must stay in the local cache")
	}
	for _, obj := range []client.Object{&corev1.Secret{}, &cmv1.Certificate{}, &acmev1.Order{}, &acmev1.Challenge{}} {
		if cachesType(objects, obj, "") {
			t.Errorf("local cache must not watch %T when cert-manager runs elsewhere", obj)
		}
	}

	if _, err := newCertManagerCluster(context.Background(), filepath.Join(t.TempDir(), "missing"), "certificates-system"); err == nil {
		t.Fatal("expected an unreadable cert-manager kubeconfig to fail startup")
	}
}

func TestCertManagerKubeconfigPathDecodes(t *testing.T) {
	data := []byte("apiVersion: apiserver.config.miloapis.com/v1alpha1\nkind: TLSCertificateOperator\ncertManagerKubeconfigPath: /etc/karmada/kubeconfig\n")
	var cfg config.TLSCertificateOperator
	if err := runtime.DecodeInto(codecs.UniversalDecoder(), data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.CertManagerKubeconfigPath != "/etc/karmada/kubeconfig" {
		t.Fatalf("got %q", cfg.CertManagerKubeconfigPath)
	}
}

func TestRequireNamespace(t *testing.T) {
	gr := schema.GroupResource{Resource: "namespaces"}
	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{name: "present"},
		{name: "missing", err: apierrors.NewNotFound(gr, "certificates-system"), wantErr: true},
		{name: "forbidden", err: apierrors.NewForbidden(gr, "certificates-system", errors.New("denied")), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &stubReader{err: tt.err}
			err := requireNamespace(context.Background(), reader, "certificates-system")
			if (err != nil) != tt.wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, tt.wantErr)
			}
			if reader.got != (client.ObjectKey{Name: "certificates-system"}) {
				t.Fatalf("looked up %v", reader.got)
			}
		})
	}
}

func cachesType(objects map[client.Object]cache.ByObject, want client.Object, namespace string) bool {
	for obj, by := range objects {
		if reflect.TypeOf(obj) != reflect.TypeOf(want) {
			continue
		}
		if namespace == "" {
			return true
		}
		_, ok := by.Namespaces[namespace]
		return ok && len(by.Namespaces) == 1
	}
	return false
}
