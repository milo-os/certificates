// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	examplev1alpha1 "go.miloapis.com/certificates/api/v1alpha1"
)

const (
	tlscertificateFinalizer = "certificates.miloapis.com/tlscertificate"
	ConditionTypeReady      = "Ready"
)

// TLSCertificateReconciler reconciles a TLSCertificate object.
type TLSCertificateReconciler struct {
	client client.Client
}

// +kubebuilder:rbac:groups=certificates.miloapis.com,resources=tlscertificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certificates.miloapis.com,resources=tlscertificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certificates.miloapis.com,resources=tlscertificates/finalizers,verbs=update

func (r *TLSCertificateReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var tlscertificate examplev1alpha1.TLSCertificate
	if err := r.client.Get(ctx, req.NamespacedName, &tlscertificate); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion with finalizer
	if !tlscertificate.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &tlscertificate)
	}

	// Ensure finalizer is present
	if !controllerutil.ContainsFinalizer(&tlscertificate, tlscertificateFinalizer) {
		controllerutil.AddFinalizer(&tlscertificate, tlscertificateFinalizer)
		if err := r.client.Update(ctx, &tlscertificate); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	// Reconcile desired state
	tlscertificate.Status.Phase = examplev1alpha1.TLSCertificatePhaseReady
	tlscertificate.Status.ObservedGeneration = tlscertificate.Generation

	apimeta.SetStatusCondition(&tlscertificate.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeReady,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: tlscertificate.Generation,
		Reason:             "TLSCertificateReady",
		Message:            "TLSCertificate is ready.",
	})

	if err := r.client.Status().Update(ctx, &tlscertificate); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	logger.Info("reconciled tlscertificate", "phase", tlscertificate.Status.Phase)
	return ctrl.Result{}, nil
}

func (r *TLSCertificateReconciler) reconcileDelete(ctx context.Context, tlscertificate *examplev1alpha1.TLSCertificate) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	controllerutil.RemoveFinalizer(tlscertificate, tlscertificateFinalizer)
	if err := r.client.Update(ctx, tlscertificate); err != nil {
		return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
	}

	logger.Info("finalized tlscertificate")
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TLSCertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		Named("tlscertificate").
		For(&examplev1alpha1.TLSCertificate{}).
		Complete(r)
}
