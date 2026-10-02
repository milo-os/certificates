// SPDX-License-Identifier: AGPL-3.0-only

package webhook

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	examplev1alpha1 "go.miloapis.com/certificates/api/v1alpha1"
)

var tlscertificateLog = logf.Log.WithName("tlscertificate-webhook")

// SetupWebhookWithManager registers the TLSCertificate webhook with the manager.
func SetupWebhookWithManager(mgr ctrl.Manager) error {
	webhook := &tlscertificateWebhook{}

	return ctrl.NewWebhookManagedBy(mgr).
		For(&examplev1alpha1.TLSCertificate{}).
		WithDefaulter(webhook).
		WithValidator(webhook).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-certificates-miloapis-com-v1alpha1-tlscertificate,mutating=true,failurePolicy=fail,sideEffects=None,groups=certificates.miloapis.com,resources=tlscertificates,verbs=create;update,versions=v1alpha1,name=mtlscertificate.kb.io,admissionReviewVersions=v1

// +kubebuilder:webhook:path=/validate-certificates-miloapis-com-v1alpha1-tlscertificate,mutating=false,failurePolicy=fail,sideEffects=None,groups=certificates.miloapis.com,resources=tlscertificates,verbs=create;update;delete,versions=v1alpha1,name=vtlscertificate.kb.io,admissionReviewVersions=v1

type tlscertificateWebhook struct{}

var _ admission.CustomDefaulter = &tlscertificateWebhook{}
var _ admission.CustomValidator = &tlscertificateWebhook{}

// Default implements admission.CustomDefaulter.
func (r *tlscertificateWebhook) Default(ctx context.Context, obj runtime.Object) error {
	tlscertificate, ok := obj.(*examplev1alpha1.TLSCertificate)
	if !ok {
		return fmt.Errorf("unexpected type %T", obj)
	}

	tlscertificateLog.Info("defaulting", "name", tlscertificate.GetName())

	// TODO: add defaulting logic here

	return nil
}

// ValidateCreate implements admission.CustomValidator.
func (r *tlscertificateWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	tlscertificate, ok := obj.(*examplev1alpha1.TLSCertificate)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T", obj)
	}

	tlscertificateLog.Info("validating create", "name", tlscertificate.GetName())

	// TODO: add validation logic here

	return nil, nil
}

// ValidateUpdate implements admission.CustomValidator.
func (r *tlscertificateWebhook) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	_, ok := oldObj.(*examplev1alpha1.TLSCertificate)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T", oldObj)
	}

	newTLSCertificate, ok := newObj.(*examplev1alpha1.TLSCertificate)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T", newObj)
	}

	tlscertificateLog.Info("validating update", "name", newTLSCertificate.GetName())

	// TODO: add validation logic here

	return nil, nil
}

// ValidateDelete implements admission.CustomValidator.
func (r *tlscertificateWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	tlscertificate, ok := obj.(*examplev1alpha1.TLSCertificate)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T", obj)
	}

	tlscertificateLog.Info("validating delete", "name", tlscertificate.GetName())

	// TODO: add validation logic here

	return nil, nil
}
