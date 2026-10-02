// SPDX-License-Identifier: AGPL-3.0-only

package webhook

import (
	"context"
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"
	"go.miloapis.com/certificates/internal/validation"
)

// SetupWebhookWithManager registers the TLSCertificate validating webhook.
func SetupWebhookWithManager(mgr ctrl.Manager, v *Validator) error {
	return ctrl.NewWebhookManagedBy(mgr, &certificatesv1alpha1.TLSCertificate{}).
		WithValidator(v).
		Complete()
}

// +kubebuilder:webhook:path=/validate-certificates-miloapis-com-v1alpha1-tlscertificate,mutating=false,failurePolicy=fail,sideEffects=None,groups=certificates.miloapis.com,resources=tlscertificates;tlscertificates/status,verbs=create;update;delete,versions=v1alpha1,name=vtlscertificate.kb.io,admissionReviewVersions=v1

// Validator rejects TLSCertificates whose names are malformed, fall under a
// denied domain suffix, or cannot be issued with the requested mode, and
// limits who may write them:
//   - create, and any update that changes the spec: WriterIdentities
//   - status writes: ServiceIdentities only; an empty list denies everyone
//   - metadata-only updates, such as finalizer and ownerRef removal during
//     deletion: WriterIdentities, ServiceIdentities or DeleterIdentities
//   - delete: WriterIdentities, ServiceIdentities or DeleterIdentities
//
// An empty WriterIdentities list turns off every check except the status one.
type Validator struct {
	DeniedDomainSuffixes []string
	WriterIdentities     []string
	ServiceIdentities    []string
	DeleterIdentities    []string
}

var _ admission.Validator[*certificatesv1alpha1.TLSCertificate] = &Validator{}

func (v *Validator) ValidateCreate(ctx context.Context, tc *certificatesv1alpha1.TLSCertificate) (admission.Warnings, error) {
	if err := v.authorize(ctx, tc, "create TLSCertificates", v.WriterIdentities); err != nil {
		return nil, err
	}
	return nil, v.validateSpec(tc)
}

func (v *Validator) ValidateUpdate(ctx context.Context, oldTC, tc *certificatesv1alpha1.TLSCertificate) (admission.Warnings, error) {
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	if req.SubResource == "status" {
		if slices.Contains(v.ServiceIdentities, req.UserInfo.Username) {
			return nil, nil
		}
		return nil, forbidden(tc, req.UserInfo.Username, "write TLSCertificate status")
	}
	if equality.Semantic.DeepEqual(oldTC.Spec, tc.Spec) {
		return nil, v.authorize(ctx, tc, "update TLSCertificates", v.WriterIdentities, v.ServiceIdentities, v.DeleterIdentities)
	}
	if err := v.authorize(ctx, tc, "change the spec of TLSCertificates", v.WriterIdentities); err != nil {
		return nil, err
	}
	return nil, v.validateSpec(tc)
}

func (v *Validator) ValidateDelete(ctx context.Context, tc *certificatesv1alpha1.TLSCertificate) (admission.Warnings, error) {
	return nil, v.authorize(ctx, tc, "delete TLSCertificates", v.WriterIdentities, v.ServiceIdentities, v.DeleterIdentities)
}

func (v *Validator) authorize(ctx context.Context, tc *certificatesv1alpha1.TLSCertificate, action string, allowed ...[]string) error {
	if len(v.WriterIdentities) == 0 {
		return nil
	}
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return apierrors.NewInternalError(err)
	}
	for _, identities := range allowed {
		if slices.Contains(identities, req.UserInfo.Username) {
			return nil
		}
	}
	return forbidden(tc, req.UserInfo.Username, action)
}

func forbidden(tc *certificatesv1alpha1.TLSCertificate, username, action string) error {
	return apierrors.NewForbidden(certificatesv1alpha1.GroupVersion.WithResource("tlscertificates").GroupResource(), tc.Name,
		fmt.Errorf("%q may not %s", username, action))
}

func (v *Validator) validateSpec(tc *certificatesv1alpha1.TLSCertificate) error {
	errs := validation.ValidateSpec(tc.Spec, field.NewPath("spec"), v.DeniedDomainSuffixes)
	if len(errs) == 0 {
		return nil
	}
	return apierrors.NewInvalid(certificatesv1alpha1.GroupVersion.WithKind("TLSCertificate").GroupKind(), tc.Name, errs)
}
