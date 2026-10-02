// SPDX-License-Identifier: AGPL-3.0-only

package validation

import (
	"net"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"
)

const maxDNSNames = 8

// IsWildcard reports whether name is a single-label wildcard.
func IsWildcard(name string) bool {
	return strings.HasPrefix(name, "*.")
}

// ResolveIssuance returns the challenge type a spec issues with: DNS01 when
// requested or when any name is a wildcard under Auto, HTTP01 otherwise.
func ResolveIssuance(spec certificatesv1alpha1.TLSCertificateSpec) certificatesv1alpha1.ChallengeType {
	switch spec.Issuance {
	case certificatesv1alpha1.IssuanceModeDNS01:
		return certificatesv1alpha1.ChallengeTypeDNS01
	case certificatesv1alpha1.IssuanceModeHTTP01:
		return certificatesv1alpha1.ChallengeTypeHTTP01
	}
	for _, n := range spec.DNSNames {
		if IsWildcard(string(n)) {
			return certificatesv1alpha1.ChallengeTypeDNS01
		}
	}
	return certificatesv1alpha1.ChallengeTypeHTTP01
}

// IsDenied reports whether name equals or falls under any of the denied
// domain suffixes.
func IsDenied(name string, deniedSuffixes []string) bool {
	base := strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(name, "*.")), ".")
	for _, suffix := range deniedSuffixes {
		suffix = strings.Trim(strings.ToLower(suffix), ".")
		if suffix == "" {
			continue
		}
		if base == suffix || strings.HasSuffix(base, "."+suffix) {
			return true
		}
	}
	return false
}

// ValidateSpec checks the names, that none fall under a denied domain suffix,
// and that the issuance mode can issue them.
func ValidateSpec(spec certificatesv1alpha1.TLSCertificateSpec, path *field.Path, deniedSuffixes []string) field.ErrorList {
	var errs field.ErrorList
	namesPath := path.Child("dnsNames")

	switch n := len(spec.DNSNames); {
	case n == 0:
		errs = append(errs, field.Required(namesPath, "at least one name is required"))
	case n > maxDNSNames:
		errs = append(errs, field.TooMany(namesPath, n, maxDNSNames))
	}

	switch spec.Issuance {
	case "", certificatesv1alpha1.IssuanceModeAuto, certificatesv1alpha1.IssuanceModeHTTP01, certificatesv1alpha1.IssuanceModeDNS01:
	default:
		errs = append(errs, field.NotSupported(path.Child("issuance"), spec.Issuance, []string{
			string(certificatesv1alpha1.IssuanceModeAuto),
			string(certificatesv1alpha1.IssuanceModeHTTP01),
			string(certificatesv1alpha1.IssuanceModeDNS01),
		}))
	}

	seen := map[string]bool{}
	for i, dnsName := range spec.DNSNames {
		name := string(dnsName)
		idxPath := namesPath.Index(i)
		if seen[name] {
			errs = append(errs, field.Duplicate(idxPath, name))
			continue
		}
		seen[name] = true

		base := strings.TrimPrefix(name, "*.")
		if strings.Contains(base, "*") {
			errs = append(errs, field.Invalid(idxPath, name, "'*' is only allowed as a leading '*.' label"))
			continue
		}
		for _, msg := range validation.IsDNS1123Subdomain(base) {
			errs = append(errs, field.Invalid(idxPath, name, msg))
		}
		for _, msg := range validateHostname(base) {
			errs = append(errs, field.Invalid(idxPath, name, msg))
		}
		if IsDenied(name, deniedSuffixes) {
			errs = append(errs, field.Forbidden(idxPath, "certificates cannot be issued for platform domains"))
		}
		if IsWildcard(name) {
			if spec.Issuance == certificatesv1alpha1.IssuanceModeHTTP01 {
				errs = append(errs, field.Invalid(idxPath, name, "wildcard names cannot be issued with HTTP01; use DNS01 or Auto"))
			}
		}
	}
	return errs
}

func validateHostname(base string) []string {
	var msgs []string
	if net.ParseIP(base) != nil {
		return append(msgs, "IP addresses are not allowed")
	}
	labels := strings.Split(base, ".")
	if len(labels) < 2 {
		msgs = append(msgs, "must have at least two labels")
	}
	for _, label := range labels {
		if len(label) > validation.DNS1123LabelMaxLength {
			msgs = append(msgs, "each label must be at most 63 characters")
		}
		if strings.HasPrefix(label, "xn--") {
			if _, err := idna.Lookup.ToUnicode(label); err != nil {
				msgs = append(msgs, "invalid punycode label "+label)
			}
		}
	}
	if suffix, _ := publicsuffix.PublicSuffix(base); suffix == base {
		msgs = append(msgs, "must not be a public suffix")
	}
	if tld := labels[len(labels)-1]; !isICANNTopLevelDomain(tld) {
		msgs = append(msgs, "top-level domain "+tld+" is not a public ICANN domain")
	}
	return msgs
}

func isICANNTopLevelDomain(tld string) bool {
	suffix, icann := publicsuffix.PublicSuffix(tld)
	return icann && suffix == tld
}
