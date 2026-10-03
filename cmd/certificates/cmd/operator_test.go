// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"testing"
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
