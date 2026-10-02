// SPDX-License-Identifier: AGPL-3.0-only

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TLSCertificatePhase represents the lifecycle state of a TLSCertificate.
// +kubebuilder:validation:Enum=Provisioning;Ready;Failed
type TLSCertificatePhase string

const (
	// TLSCertificatePhaseProvisioning indicates the tlscertificate is being set up.
	TLSCertificatePhaseProvisioning TLSCertificatePhase = "Provisioning"

	// TLSCertificatePhaseReady indicates the tlscertificate is active and healthy.
	TLSCertificatePhaseReady TLSCertificatePhase = "Ready"

	// TLSCertificatePhaseFailed indicates the tlscertificate has encountered an unrecoverable error.
	TLSCertificatePhaseFailed TLSCertificatePhase = "Failed"
)

// TLSCertificateSpec defines the desired state of TLSCertificate.
type TLSCertificateSpec struct {
	// Description is a human-readable description of this tlscertificate.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=256
	Description string `json:"description,omitempty"`
}

// TLSCertificateStatus defines the observed state of TLSCertificate.
type TLSCertificateStatus struct {
	// Phase represents the current lifecycle phase of the tlscertificate.
	//
	// +kubebuilder:validation:Optional
	Phase TLSCertificatePhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations of the tlscertificate's state.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	//
	// +kubebuilder:validation:Optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// TLSCertificate is the Schema for the tlscertificates API.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// Milo-specific: update or remove this annotation for your tlscertificate type
// +kubebuilder:metadata:annotations="discovery.miloapis.com/parent-contexts=Organization"
type TLSCertificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TLSCertificateSpec   `json:"spec,omitempty"`
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
