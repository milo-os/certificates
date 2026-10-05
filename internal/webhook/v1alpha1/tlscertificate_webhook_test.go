// SPDX-License-Identifier: AGPL-3.0-only

package webhook

import (
	"context"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"
)

const (
	writer  = "system:control@networking.datumapis.com"
	service = "system:control@certificates.miloapis.com"
	tenant  = "tenant@example.com"
)

func requestContext(user, subresource string) context.Context {
	return admission.NewContextWithRequest(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UserInfo:    authenticationv1.UserInfo{Username: user},
		SubResource: subresource,
	}})
}

func tlsCertificate(issuance certificatesv1alpha1.IssuanceMode, names ...certificatesv1alpha1.DNSName) *certificatesv1alpha1.TLSCertificate {
	return &certificatesv1alpha1.TLSCertificate{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec:       certificatesv1alpha1.TLSCertificateSpec{DNSNames: names, Issuance: issuance},
	}
}

const deleter = "system:serviceaccount:kube-system:namespace-controller"

func newValidator() *Validator {
	return &Validator{
		DeniedDomainSuffixes: []string{"datumproxy.net", "acme-dns.example.net"},
		WriterIdentities:     []string{writer},
		ServiceIdentities:    []string{service},
		DeleterIdentities:    []string{deleter},
	}
}

func TestValidateCreate(t *testing.T) {
	tests := []struct {
		name    string
		user    string
		tc      *certificatesv1alpha1.TLSCertificate
		invalid bool
		denied  bool
	}{
		{name: "http01 name", user: writer, tc: tlsCertificate(certificatesv1alpha1.IssuanceModeHTTP01, "app.example.com")},
		{name: "auto wildcard", user: writer, tc: tlsCertificate(certificatesv1alpha1.IssuanceModeAuto, "*.example.com")},
		{name: "dns01 wildcard", user: writer, tc: tlsCertificate(certificatesv1alpha1.IssuanceModeDNS01, "*.example.com", "example.com")},
		{name: "http01 wildcard", user: writer, tc: tlsCertificate(certificatesv1alpha1.IssuanceModeHTTP01, "*.example.com"), invalid: true},
		{name: "denied suffix", user: writer, tc: tlsCertificate(certificatesv1alpha1.IssuanceModeAuto, "app.datumproxy.net"), invalid: true},
		{name: "delegation zone", user: writer, tc: tlsCertificate(certificatesv1alpha1.IssuanceModeAuto, "x.acme-dns.example.net"), invalid: true},
		{name: "public suffix wildcard", user: writer, tc: tlsCertificate(certificatesv1alpha1.IssuanceModeDNS01, "*.co.uk"), invalid: true},
		{name: "tenant create", user: tenant, tc: tlsCertificate(certificatesv1alpha1.IssuanceModeAuto, "app.example.com"), denied: true},
		{name: "service create", user: service, tc: tlsCertificate(certificatesv1alpha1.IssuanceModeAuto, "app.example.com"), denied: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newValidator().ValidateCreate(requestContext(tt.user, ""), tt.tc)
			switch {
			case tt.denied:
				if !apierrors.IsForbidden(err) {
					t.Fatalf("expected forbidden, got %v", err)
				}
			case tt.invalid:
				if !apierrors.IsInvalid(err) {
					t.Fatalf("expected invalid, got %v", err)
				}
			case err != nil:
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestValidateUpdate(t *testing.T) {
	oldTC := tlsCertificate(certificatesv1alpha1.IssuanceModeAuto, "app.example.com")
	metadataOnly := oldTC.DeepCopy()
	metadataOnly.Finalizers = []string{"certificates.miloapis.com/tlscertificate"}
	specChange := oldTC.DeepCopy()
	specChange.Spec.Issuance = certificatesv1alpha1.IssuanceModeHTTP01

	tests := []struct {
		name        string
		validator   *Validator
		user        string
		subresource string
		newTC       *certificatesv1alpha1.TLSCertificate
		allowed     bool
	}{
		{name: "service writes status", user: service, subresource: "status", newTC: oldTC, allowed: true},
		{name: "writer writes status", user: writer, subresource: "status", newTC: oldTC},
		{name: "tenant writes status", user: tenant, subresource: "status", newTC: oldTC},
		{name: "status denied to everyone without service identities", validator: &Validator{WriterIdentities: []string{writer}}, user: service, subresource: "status", newTC: oldTC},
		{name: "status denied without any identities", validator: &Validator{}, user: tenant, subresource: "status", newTC: oldTC},
		{name: "service changes finalizers", user: service, newTC: metadataOnly, allowed: true},
		{name: "writer changes finalizers", user: writer, newTC: metadataOnly, allowed: true},
		{name: "tenant changes finalizers", user: tenant, newTC: metadataOnly},
		{name: "deleter changes finalizers", user: deleter, newTC: metadataOnly, allowed: true},
		{name: "deleter changes spec", user: deleter, newTC: specChange},
		{name: "service changes spec", user: service, newTC: specChange},
		{name: "writer changes spec", user: writer, newTC: specChange, allowed: true},
		{name: "tenant changes spec", user: tenant, newTC: specChange},
		{name: "writer gating off allows tenant spec change", validator: &Validator{ServiceIdentities: []string{service}}, user: tenant, newTC: specChange, allowed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := tt.validator
			if v == nil {
				v = newValidator()
			}
			_, err := v.ValidateUpdate(requestContext(tt.user, tt.subresource), oldTC, tt.newTC)
			if tt.allowed && err != nil {
				t.Fatalf("expected allowed, got %v", err)
			}
			if !tt.allowed && !apierrors.IsForbidden(err) {
				t.Fatalf("expected forbidden, got %v", err)
			}
		})
	}
}

func TestValidateDelete(t *testing.T) {
	tc := tlsCertificate(certificatesv1alpha1.IssuanceModeAuto, "app.example.com")
	for user, allowed := range map[string]bool{writer: true, service: true, deleter: true, tenant: false} {
		_, err := newValidator().ValidateDelete(requestContext(user, ""), tc)
		if allowed && err != nil {
			t.Errorf("%s: expected allowed, got %v", user, err)
		}
		if !allowed && !apierrors.IsForbidden(err) {
			t.Errorf("%s: expected forbidden, got %v", user, err)
		}
	}
	if _, err := (&Validator{ServiceIdentities: []string{service}}).ValidateDelete(requestContext(tenant, ""), tc); err != nil {
		t.Errorf("expected delete to be unrestricted when writer gating is off, got %v", err)
	}
}
