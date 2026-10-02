// SPDX-License-Identifier: AGPL-3.0-only

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IssuanceMode selects how the certificate authority validates control of the
// requested names.
// +kubebuilder:validation:Enum=Auto;HTTP01;DNS01
type IssuanceMode string

const (
	// IssuanceModeAuto resolves to DNS01 when any name is a wildcard and to
	// HTTP01 otherwise.
	IssuanceModeAuto IssuanceMode = "Auto"

	// IssuanceModeHTTP01 validates each name by serving a token over HTTP on
	// port 80. Wildcard names cannot use this mode.
	IssuanceModeHTTP01 IssuanceMode = "HTTP01"

	// IssuanceModeDNS01 validates each name through a TXT record that the
	// service publishes in its delegation zone, reached through a CNAME the
	// name's owner publishes to status.delegationTarget.
	IssuanceModeDNS01 IssuanceMode = "DNS01"
)

// ChallengeType is a resolved issuance mode: the ACME challenge type used to
// validate the names.
// +kubebuilder:validation:Enum=HTTP01;DNS01
type ChallengeType string

const (
	// ChallengeTypeHTTP01 is the ACME HTTP-01 challenge.
	ChallengeTypeHTTP01 ChallengeType = "HTTP01"

	// ChallengeTypeDNS01 is the ACME DNS-01 challenge.
	ChallengeTypeDNS01 ChallengeType = "DNS01"
)

// DNSRecordPurpose explains why a DNS record must be published.
// +kubebuilder:validation:Enum=Routing;Certificate
type DNSRecordPurpose string

const (
	// DNSRecordPurposeRouting marks a record that directs traffic for the name.
	DNSRecordPurposeRouting DNSRecordPurpose = "Routing"

	// DNSRecordPurposeCertificate marks a record that issuance depends on.
	DNSRecordPurposeCertificate DNSRecordPurpose = "Certificate"
)

// ChallengeState is the lifecycle state of an ACME challenge.
// +kubebuilder:validation:Enum=Pending;Valid;Invalid
type ChallengeState string

const (
	// ChallengeStatePending means the certificate authority has not yet
	// validated the challenge.
	ChallengeStatePending ChallengeState = "Pending"

	// ChallengeStateValid means the certificate authority accepted the challenge.
	ChallengeStateValid ChallengeState = "Valid"

	// ChallengeStateInvalid means the certificate authority rejected the
	// challenge.
	ChallengeStateInvalid ChallengeState = "Invalid"
)

// Condition types reported on a TLSCertificate.
const (
	// ConditionAccepted reports whether the spec can be issued: the names are
	// valid and the issuance mode supports them.
	ConditionAccepted = "Accepted"

	// ConditionDNSDelegationReady reports, for DNS01 issuance, whether every
	// _acme-challenge CNAME resolves to the target the service assigned.
	ConditionDNSDelegationReady = "DNSDelegationReady"

	// ConditionIssuing reports whether an ACME order is in flight.
	ConditionIssuing = "Issuing"

	// ConditionReady reports whether an unexpired certificate Secret exists in
	// the project.
	ConditionReady = "Ready"
)

// TLSCertificateSpec defines the desired state of TLSCertificate.
//
// +kubebuilder:validation:XValidation:rule="!has(self.issuance) || self.issuance != 'HTTP01' || !self.dnsNames.exists(n, n.startsWith('*.'))",message="wildcard names require DNS01 or Auto issuance"
// +kubebuilder:validation:XValidation:rule="has(self.secretName) == has(oldSelf.secretName) && (!has(self.secretName) || self.secretName == oldSelf.secretName)",message="secretName is immutable"
type TLSCertificateSpec struct {
	// DNSNames are the hostnames the certificate covers. Each name is a
	// lowercase RFC 1123 hostname. A name may start with a single "*." label
	// to cover exactly one additional label; "*" is not allowed anywhere else.
	//
	// The service does not verify that the project controls these names.
	// Callers must create a TLSCertificate only for names whose ownership they
	// have already verified. Names under the platform's own domains are
	// rejected.
	//
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +listType=set
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="dnsNames is immutable"
	DNSNames []DNSName `json:"dnsNames"`

	// Issuance selects how control of the names is validated. Auto resolves to
	// DNS01 when any name is a wildcard and to HTTP01 otherwise. Immutable.
	//
	// +optional
	// +kubebuilder:default=Auto
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="issuance is immutable"
	Issuance IssuanceMode `json:"issuance,omitempty"`

	// SecretName names the kubernetes.io/tls Secret written to the
	// TLSCertificate's namespace. Defaults to "<metadata.name>-tls".
	//
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	SecretName string `json:"secretName,omitempty"`
}

// DNSName is a lowercase RFC 1123 hostname, optionally prefixed with "*.".
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^(\*\.)?[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)+$`
// +kubebuilder:validation:XValidation:rule="!self.matches('^[0-9.]+$')",message="IP addresses are not allowed"
// +kubebuilder:validation:XValidation:rule="!self.contains('*') || (self.startsWith('*.') && !self.substring(1).contains('*'))",message="'*' is only allowed as a leading '*.' label"
// +kubebuilder:validation:XValidation:rule="!self.startsWith('*.') || self.substring(2).contains('.')",message="a wildcard must cover a name with at least two labels"
type DNSName string

// SecretReference names a Secret in the TLSCertificate's namespace.
type SecretReference struct {
	// Name is the Secret's name.
	Name string `json:"name"`
}

// ServiceSecretReference locates the issued Secret on the cluster that runs
// the certificate service.
type ServiceSecretReference struct {
	// Namespace is the Secret's namespace on the service cluster.
	Namespace string `json:"namespace"`

	// Name is the Secret's name.
	Name string `json:"name"`
}

// RequiredDNSRecord is a DNS record the name's owner must publish before
// issuance can complete.
type RequiredDNSRecord struct {
	// Name is the fully qualified record name.
	Name string `json:"name"`

	// Type is the DNS record type, such as CNAME.
	Type string `json:"type"`

	// Content is the record value.
	Content string `json:"content"`

	// Purpose explains what the record is for.
	Purpose DNSRecordPurpose `json:"purpose"`
}

// ACMEChallenge is a live ACME challenge for one name.
//
// For HTTP01, the consumer serves GET /.well-known/acme-challenge/<token>
// with the body <key> on dnsName. For DNS01 the service's issuer publishes
// the TXT record itself and the entry is informational.
type ACMEChallenge struct {
	// DNSName is the name being validated.
	DNSName string `json:"dnsName"`

	// Type is the challenge type.
	Type ChallengeType `json:"type"`

	// Token is the challenge token.
	Token string `json:"token"`

	// Key is the key authorization served for HTTP01, or the TXT value for
	// DNS01.
	Key string `json:"key"`

	// State is the challenge's validation state.
	State ChallengeState `json:"state"`
}

// TLSCertificateStatus defines the observed state of TLSCertificate.
type TLSCertificateStatus struct {
	// Issuance is the resolved issuance mode.
	//
	// +optional
	Issuance ChallengeType `json:"issuance,omitempty"`

	// SecretRef names the kubernetes.io/tls Secret holding the issued
	// certificate.
	//
	// +optional
	SecretRef *SecretReference `json:"secretRef,omitempty"`

	// ServiceSecretRef locates the service's own copy of the issued Secret on
	// the cluster that runs the certificate service. It is kept in sync with
	// every issuance and survives suspended renewal. Platform components that distribute the certificate
	// read it from there with their own credentials rather than from the
	// project copy, which project editors can change.
	//
	// +optional
	ServiceSecretRef *ServiceSecretReference `json:"serviceSecretRef,omitempty"`

	// DelegationTarget is the name the _acme-challenge record must CNAME to
	// for DNS01 issuance, set only when the spec has exactly one DNS01 base
	// name. status.requiredDNSRecords is authoritative and lists the target
	// for every name. Targets are random, held by the service per project
	// namespace and name, and stay the same when a TLSCertificate for the same
	// name is recreated in the same namespace. They are never derived from the
	// hostname.
	//
	// +optional
	DelegationTarget string `json:"delegationTarget,omitempty"`

	// NotBefore is when the current certificate becomes valid.
	//
	// +optional
	NotBefore *metav1.Time `json:"notBefore,omitempty"`

	// NotAfter is when the current certificate expires.
	//
	// +optional
	NotAfter *metav1.Time `json:"notAfter,omitempty"`

	// RenewalTime is when the service will next renew the certificate.
	//
	// +optional
	RenewalTime *metav1.Time `json:"renewalTime,omitempty"`

	// RequiredDNSRecords are the records the name's owner must publish before
	// issuance can complete. HTTP01 issuance emits none; routing the names to
	// the consumer is the consumer's concern.
	//
	// +optional
	// +listType=atomic
	RequiredDNSRecords []RequiredDNSRecord `json:"requiredDNSRecords,omitempty"`

	// Challenges are the live ACME challenges the consumer may need to serve.
	//
	// +optional
	// +listType=atomic
	Challenges []ACMEChallenge `json:"challenges,omitempty"`

	// Conditions are Accepted, DNSDelegationReady, Issuing and Ready.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation the service acted on.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// TLSCertificate requests a publicly trusted TLS certificate for a set of
// hostnames and delivers it as a kubernetes.io/tls Secret in the same
// namespace.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 63",message="metadata.name must be at most 63 characters"
// +kubebuilder:printcolumn:name="Issuance",type=string,JSONPath=`.status.issuance`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.status.secretRef.name`
// +kubebuilder:printcolumn:name="NotAfter",type=string,JSONPath=`.status.notAfter`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:metadata:annotations="discovery.miloapis.com/parent-contexts=Project"
type TLSCertificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec   TLSCertificateSpec   `json:"spec"`
	Status TLSCertificateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TLSCertificateList contains a list of TLSCertificate.
type TLSCertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TLSCertificate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TLSCertificate{}, &TLSCertificateList{})
}
