// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/multicluster-runtime/pkg/multicluster"
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
