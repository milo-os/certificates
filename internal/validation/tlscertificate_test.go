// SPDX-License-Identifier: AGPL-3.0-only

package validation

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"
)

func spec(issuance certificatesv1alpha1.IssuanceMode, names ...certificatesv1alpha1.DNSName) certificatesv1alpha1.TLSCertificateSpec {
	return certificatesv1alpha1.TLSCertificateSpec{DNSNames: names, Issuance: issuance}
}

func TestValidateSpec(t *testing.T) {
	denied := []string{"datumproxy.net", "acme-dns.example.net"}
	tests := []struct {
		name  string
		spec  certificatesv1alpha1.TLSCertificateSpec
		valid bool
	}{
		{name: "plain name", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "app.example.com"), valid: true},
		{name: "wildcard dns01", spec: spec(certificatesv1alpha1.IssuanceModeDNS01, "*.example.com"), valid: true},
		{name: "punycode", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "xn--bcher-kva.de"), valid: true},
		{name: "punycode tld", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "example.xn--p1ai"), valid: true},
		{name: "private suffix subdomain", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "foo.github.io"), valid: true},
		{name: "internal tld", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "foo.internal")},
		{name: "local wildcard", spec: spec(certificatesv1alpha1.IssuanceModeDNS01, "*.foo.local")},
		{name: "unlisted tld", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "app.example")},
		{name: "unlisted tld subdomain", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "app.foo.example")},
		{name: "local tld subdomain", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "app.foo.local")},
		{name: "wildcard-only tld exception", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "www.ck"), valid: true},
		{name: "lookalike of denied suffix", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "notdatumproxy.net"), valid: true},
		{name: "wildcard http01", spec: spec(certificatesv1alpha1.IssuanceModeHTTP01, "*.example.com")},
		{name: "denied apex", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "datumproxy.net")},
		{name: "denied subdomain", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "a.b.datumproxy.net")},
		{name: "denied wildcard", spec: spec(certificatesv1alpha1.IssuanceModeDNS01, "*.datumproxy.net")},
		{name: "delegation zone", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "x.acme-dns.example.net")},
		{name: "label over 63", spec: spec(certificatesv1alpha1.IssuanceModeAuto, certificatesv1alpha1.DNSName(strings.Repeat("a", 64)+".com"))},
		{name: "ip literal", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "1.2.3.4")},
		{name: "invalid punycode", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "xn--zz.com")},
		{name: "public suffix wildcard", spec: spec(certificatesv1alpha1.IssuanceModeDNS01, "*.co.uk")},
		{name: "public suffix", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "co.uk")},
		{name: "single label", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "localhost")},
		{name: "star in the middle", spec: spec(certificatesv1alpha1.IssuanceModeDNS01, "a.*.example.com")},
		{name: "duplicates", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "a.example.com", "a.example.com")},
		{name: "too many", spec: spec(certificatesv1alpha1.IssuanceModeAuto, "a.example.com", "b.example.com", "c.example.com",
			"d.example.com", "e.example.com", "f.example.com", "g.example.com", "h.example.com", "i.example.com")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateSpec(tt.spec, field.NewPath("spec"), denied)
			if tt.valid && len(errs) > 0 {
				t.Fatalf("expected valid, got %v", errs)
			}
			if !tt.valid && len(errs) == 0 {
				t.Fatal("expected errors")
			}
		})
	}
}

func TestValidateSpecWildcardOnlyCountryTLDs(t *testing.T) {
	for _, tld := range []string{"np", "ck", "er", "fk", "jm", "kh", "mm", "pg"} {
		tests := []struct {
			name  string
			spec  certificatesv1alpha1.TLSCertificateSpec
			valid bool
		}{
			{name: "registrable name", spec: spec(certificatesv1alpha1.IssuanceModeAuto, certificatesv1alpha1.DNSName("foo.com."+tld)), valid: true},
			{name: "subdomain", spec: spec(certificatesv1alpha1.IssuanceModeAuto, certificatesv1alpha1.DNSName("app.foo.com."+tld)), valid: true},
			{name: "wildcard", spec: spec(certificatesv1alpha1.IssuanceModeDNS01, certificatesv1alpha1.DNSName("*.foo.com."+tld)), valid: true},
			{name: "public suffix", spec: spec(certificatesv1alpha1.IssuanceModeAuto, certificatesv1alpha1.DNSName("com."+tld))},
			{name: "public suffix wildcard", spec: spec(certificatesv1alpha1.IssuanceModeDNS01, certificatesv1alpha1.DNSName("*.com."+tld))},
			{name: "bare tld", spec: spec(certificatesv1alpha1.IssuanceModeAuto, certificatesv1alpha1.DNSName(tld))},
		}
		for _, tt := range tests {
			t.Run(tld+"/"+tt.name, func(t *testing.T) {
				errs := ValidateSpec(tt.spec, field.NewPath("spec"), nil)
				if tt.valid && len(errs) > 0 {
					t.Fatalf("expected valid, got %v", errs)
				}
				if !tt.valid && len(errs) == 0 {
					t.Fatal("expected errors")
				}
			})
		}
	}
}

func TestResolveIssuance(t *testing.T) {
	if got := ResolveIssuance(spec(certificatesv1alpha1.IssuanceModeAuto, "a.example.com")); got != certificatesv1alpha1.ChallengeTypeHTTP01 {
		t.Errorf("auto plain: got %s", got)
	}
	if got := ResolveIssuance(spec(certificatesv1alpha1.IssuanceModeAuto, "a.example.com", "*.example.com")); got != certificatesv1alpha1.ChallengeTypeDNS01 {
		t.Errorf("auto wildcard: got %s", got)
	}
	if got := ResolveIssuance(spec(certificatesv1alpha1.IssuanceModeDNS01, "a.example.com")); got != certificatesv1alpha1.ChallengeTypeDNS01 {
		t.Errorf("dns01: got %s", got)
	}
}
