// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"go.miloapis.com/milo/pkg/downstreamclient"
	milosource "go.miloapis.com/milo/pkg/multicluster-runtime/source"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	mcbuilder "sigs.k8s.io/multicluster-runtime/pkg/builder"
	mchandler "sigs.k8s.io/multicluster-runtime/pkg/handler"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	"sigs.k8s.io/multicluster-runtime/pkg/multicluster"
	mcreconcile "sigs.k8s.io/multicluster-runtime/pkg/reconcile"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"
	"go.miloapis.com/certificates/internal/validation"
)

const (
	tlsCertificateFinalizer = "certificates.miloapis.com/tlscertificate"
	fieldManager            = "certificates.miloapis.com"
	issuingSecretSuffix     = "-issuing"

	// UpstreamUIDLabel binds every service-side resource to the UID of the
	// TLSCertificate it was created for.
	UpstreamUIDLabel = "certificates.miloapis.com/upstream-uid"

	defaultResyncInterval          = time.Hour
	defaultMaxConcurrentReconciles = 8
	maxConditionMessage            = 512
)

var knownConditions = []string{
	certificatesv1alpha1.ConditionAccepted,
	certificatesv1alpha1.ConditionDNSDelegationReady,
	certificatesv1alpha1.ConditionIssuing,
	certificatesv1alpha1.ConditionReady,
}

// TLSCertificateReconciler issues certificates for TLSCertificates in every
// engaged project control plane. Each TLSCertificate is backed by a
// cert-manager Certificate in CertificateNamespace on the local cluster, and
// the issued key pair is copied back into the project as a kubernetes.io/tls
// Secret.
type TLSCertificateReconciler struct {
	CertificateNamespace string
	HTTP01ClusterIssuer  string
	DeniedDomainSuffixes []string

	ResyncInterval          time.Duration
	MaxConcurrentReconciles int

	mgr mcmanager.Manager
}

// +kubebuilder:rbac:groups=certificates.miloapis.com,resources=tlscertificates,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=certificates.miloapis.com,resources=tlscertificates/status,verbs=update;patch
// +kubebuilder:rbac:groups=certificates.miloapis.com,resources=tlscertificates/finalizers,verbs=update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete,namespace=certificates-system
// +kubebuilder:rbac:groups=acme.cert-manager.io,resources=orders;challenges,verbs=get;list;watch,namespace=certificates-system
// +kubebuilder:rbac:groups=core,resources=secrets;configmaps,verbs=get;list;watch;create;update;patch;delete,namespace=certificates-system

func (r *TLSCertificateReconciler) Reconcile(ctx context.Context, req mcreconcile.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("cluster", req.ClusterName)
	ctx = log.IntoContext(ctx, logger)

	cl, err := r.mgr.GetCluster(ctx, req.ClusterName)
	if err != nil {
		return ctrl.Result{}, err
	}
	projectClient := cl.GetClient()

	var tc certificatesv1alpha1.TLSCertificate
	if err := projectClient.Get(ctx, req.NamespacedName, &tc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	certName := serviceCertificateName(req.ClusterName, tc.Namespace, tc.Name, tc.UID)

	if !tc.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.finalize(ctx, cl, req.ClusterName, &tc, certName)
	}

	if !controllerutil.ContainsFinalizer(&tc, tlsCertificateFinalizer) {
		base := tc.DeepCopy()
		controllerutil.AddFinalizer(&tc, tlsCertificateFinalizer)
		if err := projectClient.Patch(ctx, &tc, client.MergeFrom(base)); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
	}

	desired := tc.DeepCopy()
	result, err := r.computeStatus(ctx, cl, req.ClusterName, desired, certName)
	if err != nil {
		return ctrl.Result{}, err
	}

	if !equality.Semantic.DeepEqual(tc.Status, desired.Status) {
		if err := projectClient.Status().Update(ctx, desired); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
		}
	}
	return result, nil
}

// computeStatus rebuilds tc.Status from tc.Spec and service-side state. It
// reads nothing from the existing status except condition transition times.
func (r *TLSCertificateReconciler) computeStatus(
	ctx context.Context,
	cl cluster.Cluster,
	clusterName multicluster.ClusterName,
	tc *certificatesv1alpha1.TLSCertificate,
	certName string,
) (ctrl.Result, error) {
	localClient := r.mgr.GetLocalManager().GetClient()

	mode := validation.ResolveIssuance(tc.Spec)
	secretName := projectSecretName(tc)
	var conditions []metav1.Condition
	for _, c := range tc.Status.Conditions {
		if slices.Contains(knownConditions, c.Type) {
			conditions = append(conditions, c)
		}
	}
	tc.Status = certificatesv1alpha1.TLSCertificateStatus{
		Issuance:           mode,
		SecretRef:          &certificatesv1alpha1.SecretReference{Name: secretName},
		Conditions:         conditions,
		ObservedGeneration: tc.Generation,
	}
	result := ctrl.Result{RequeueAfter: r.resyncInterval()}

	cert := &cmv1.Certificate{ObjectMeta: metav1.ObjectMeta{Name: certName, Namespace: r.CertificateNamespace}}
	if err := localClient.Get(ctx, client.ObjectKeyFromObject(cert), cert); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("getting certificate %s: %w", certName, err)
		}
		cert = nil
	}
	if cert != nil && cert.Labels[UpstreamUIDLabel] != string(tc.UID) {
		r.setCondition(tc, certificatesv1alpha1.ConditionAccepted, metav1.ConditionFalse, "CertificateConflict",
			"A service-side certificate with this name belongs to another TLSCertificate.")
		apimeta.RemoveStatusCondition(&tc.Status.Conditions, certificatesv1alpha1.ConditionDNSDelegationReady)
		r.setCondition(tc, certificatesv1alpha1.ConditionIssuing, metav1.ConditionFalse, "CertificateConflict", "Issuance is blocked.")
		r.setCondition(tc, certificatesv1alpha1.ConditionReady, metav1.ConditionFalse, "CertificateConflict", "Issuance is blocked.")
		return result, nil
	}

	issuer, reason, msg := r.issuerFor(tc, mode)
	if issuer == "" {
		if err := r.suspend(ctx, cert); err != nil {
			return ctrl.Result{}, err
		}
		r.setCondition(tc, certificatesv1alpha1.ConditionAccepted, metav1.ConditionFalse, reason, msg)
		apimeta.RemoveStatusCondition(&tc.Status.Conditions, certificatesv1alpha1.ConditionDNSDelegationReady)
		r.setCondition(tc, certificatesv1alpha1.ConditionIssuing, metav1.ConditionFalse, "NotAccepted", "Issuance and renewal are suspended because the spec was not accepted.")
		r.setCondition(tc, certificatesv1alpha1.ConditionReady, metav1.ConditionFalse, "NotAccepted", "The spec was not accepted.")
		return result, nil
	}
	r.setCondition(tc, certificatesv1alpha1.ConditionAccepted, metav1.ConditionTrue, "Accepted", fmt.Sprintf("Issuing with %s.", mode))

	cert, err := r.ensureCertificate(ctx, clusterName, tc, certName, issuer)
	if err != nil {
		return ctrl.Result{}, err
	}
	acmeErr, err := r.observeChallenges(ctx, tc, certName)
	if err != nil {
		return ctrl.Result{}, err
	}
	r.observeCertificate(tc, cert, acmeErr)

	notAfter, err := r.syncProjectSecret(ctx, cl, tc, certName, secretName)
	if err != nil {
		return ctrl.Result{}, err
	}
	if notAfter != nil {
		if until := time.Until(notAfter.Time); until > 0 && until < result.RequeueAfter {
			result.RequeueAfter = until
		}
	}
	return result, nil
}

func (r *TLSCertificateReconciler) issuerFor(tc *certificatesv1alpha1.TLSCertificate, mode certificatesv1alpha1.ChallengeType) (string, string, string) {
	if errs := validation.ValidateSpec(tc.Spec, field.NewPath("spec"), r.DeniedDomainSuffixes); len(errs) > 0 {
		return "", "InvalidSpec", truncate(errs.ToAggregate().Error())
	}
	switch mode {
	case certificatesv1alpha1.ChallengeTypeDNS01:
		return "", "IssuanceModeUnavailable", "DNS01 issuance is not available."
	default:
		if r.HTTP01ClusterIssuer == "" {
			return "", "IssuanceModeUnavailable", "HTTP01 issuance is not available."
		}
		return r.HTTP01ClusterIssuer, "", ""
	}
}

// suspend deletes the service-side cert-manager Certificate so cert-manager
// stops issuing and renewing it. The service's own copy of the issued key pair
// is kept, whatever cert-manager does with the Secret it wrote.
func (r *TLSCertificateReconciler) suspend(ctx context.Context, cert *cmv1.Certificate) error {
	if cert == nil {
		return nil
	}
	if err := client.IgnoreNotFound(r.mgr.GetLocalManager().GetClient().Delete(ctx, cert)); err != nil {
		return fmt.Errorf("suspending certificate %s: %w", cert.Name, err)
	}
	log.FromContext(ctx).Info("suspended certificate", "certificate", cert.Name)
	return nil
}

func (r *TLSCertificateReconciler) ensureCertificate(
	ctx context.Context,
	clusterName multicluster.ClusterName,
	tc *certificatesv1alpha1.TLSCertificate,
	certName, issuer string,
) (*cmv1.Certificate, error) {
	labels := serviceLabels(clusterName, tc)
	dnsNames := make([]string, 0, len(tc.Spec.DNSNames))
	for _, n := range tc.Spec.DNSNames {
		dnsNames = append(dnsNames, string(n))
	}

	cert := &cmv1.Certificate{ObjectMeta: metav1.ObjectMeta{Name: certName, Namespace: r.CertificateNamespace}}
	op, err := controllerutil.CreateOrUpdate(ctx, r.mgr.GetLocalManager().GetClient(), cert, func() error {
		if !cert.CreationTimestamp.IsZero() && cert.Labels[UpstreamUIDLabel] != string(tc.UID) {
			return fmt.Errorf("certificate %s belongs to another TLSCertificate", certName)
		}
		if cert.Labels == nil {
			cert.Labels = map[string]string{}
		}
		for k, v := range labels {
			cert.Labels[k] = v
		}
		cert.Spec.SecretName = issuingSecretName(certName)
		cert.Spec.SecretTemplate = &cmv1.CertificateSecretTemplate{
			Labels: map[string]string{UpstreamUIDLabel: string(tc.UID)},
		}
		cert.Spec.DNSNames = dnsNames
		cert.Spec.IssuerRef = cmmeta.ObjectReference{
			Name:  issuer,
			Kind:  cmv1.ClusterIssuerKind,
			Group: "cert-manager.io",
		}
		cert.Spec.PrivateKey = &cmv1.CertificatePrivateKey{RotationPolicy: cmv1.RotationPolicyAlways}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ensuring certificate %s: %w", certName, err)
	}
	if op != controllerutil.OperationResultNone {
		log.FromContext(ctx).Info("certificate reconciled", "certificate", certName, "operation", op)
	}
	return cert, nil
}

func (r *TLSCertificateReconciler) observeChallenges(ctx context.Context, tc *certificatesv1alpha1.TLSCertificate, certName string) (string, error) {
	localClient := r.mgr.GetLocalManager().GetClient()

	var orders acmev1.OrderList
	if err := localClient.List(ctx, &orders, client.InNamespace(r.CertificateNamespace)); err != nil {
		return "", fmt.Errorf("listing orders: %w", err)
	}
	orderUIDs := map[types.UID]bool{}
	var latest *acmev1.Order
	for i := range orders.Items {
		order := &orders.Items[i]
		if order.Annotations[cmv1.CertificateNameKey] != certName {
			continue
		}
		orderUIDs[order.UID] = true
		if latest == nil || latest.CreationTimestamp.Before(&order.CreationTimestamp) {
			latest = order
		}
	}

	var challenges acmev1.ChallengeList
	if err := localClient.List(ctx, &challenges, client.InNamespace(r.CertificateNamespace)); err != nil {
		return "", fmt.Errorf("listing challenges: %w", err)
	}

	var acmeErr string
	var observed []certificatesv1alpha1.ACMEChallenge
	for i := range challenges.Items {
		ch := &challenges.Items[i]
		owner := metav1.GetControllerOf(ch)
		if owner == nil || !orderUIDs[owner.UID] {
			continue
		}
		dnsName := ch.Spec.DNSName
		if ch.Spec.Wildcard {
			dnsName = "*." + dnsName
		}
		chType := certificatesv1alpha1.ChallengeTypeHTTP01
		if ch.Spec.Type == acmev1.ACMEChallengeTypeDNS01 {
			chType = certificatesv1alpha1.ChallengeTypeDNS01
		}
		observed = append(observed, certificatesv1alpha1.ACMEChallenge{
			DNSName: dnsName,
			Type:    chType,
			Token:   ch.Spec.Token,
			Key:     ch.Spec.Key,
			State:   challengeState(ch.Status.State),
		})
		if ch.Status.Reason != "" {
			acmeErr = ch.Status.Reason
		}
	}
	slices.SortFunc(observed, func(a, b certificatesv1alpha1.ACMEChallenge) int {
		return strings.Compare(a.DNSName+"/"+a.Token, b.DNSName+"/"+b.Token)
	})
	tc.Status.Challenges = observed

	if acmeErr == "" && latest != nil {
		acmeErr = latest.Status.Reason
	}
	return truncate(acmeErr), nil
}

func challengeState(s acmev1.State) certificatesv1alpha1.ChallengeState {
	switch s {
	case acmev1.Valid:
		return certificatesv1alpha1.ChallengeStateValid
	case acmev1.Invalid, acmev1.Errored, acmev1.Expired:
		return certificatesv1alpha1.ChallengeStateInvalid
	default:
		return certificatesv1alpha1.ChallengeStatePending
	}
}

func (r *TLSCertificateReconciler) observeCertificate(tc *certificatesv1alpha1.TLSCertificate, cert *cmv1.Certificate, acmeErr string) {
	tc.Status.RenewalTime = cert.Status.RenewalTime

	issuing := certManagerCondition(cert, cmv1.CertificateConditionIssuing)
	msg := ""
	if issuing != nil {
		msg = truncate(issuing.Message)
	}
	if acmeErr != "" {
		msg = acmeErr
	}
	switch {
	case issuing != nil && issuing.Status == cmmeta.ConditionTrue:
		r.setCondition(tc, certificatesv1alpha1.ConditionIssuing, metav1.ConditionTrue, "OrderInFlight", msg)
	case issuing != nil && issuing.Reason == "Failed":
		r.setCondition(tc, certificatesv1alpha1.ConditionIssuing, metav1.ConditionFalse, "IssuanceFailed", msg)
	default:
		r.setCondition(tc, certificatesv1alpha1.ConditionIssuing, metav1.ConditionFalse, "NoOrderInFlight", "No ACME order is in flight.")
	}
}

func certManagerCondition(cert *cmv1.Certificate, t cmv1.CertificateConditionType) *cmv1.CertificateCondition {
	for i := range cert.Status.Conditions {
		if cert.Status.Conditions[i].Type == t {
			return &cert.Status.Conditions[i]
		}
	}
	return nil
}

// storeIssued copies the key pair cert-manager issued into a Secret the service
// owns, named certName and owned by nothing, so cert-manager or garbage
// collection removing its own Secret never takes the certificate with it. The
// copy is replaced only by a valid certificate for tc that covers every
// requested name exactly, whose key matches, and that was issued after the
// one already stored. Ordering by issue time lets an emergency re-key with a
// shorter lifetime replace a compromised key straight away.
func (r *TLSCertificateReconciler) storeIssued(ctx context.Context, tc *certificatesv1alpha1.TLSCertificate, certName string) (*corev1.Secret, error) {
	c := r.mgr.GetLocalManager().GetClient()

	stored := &corev1.Secret{}
	err := c.Get(ctx, types.NamespacedName{Namespace: r.CertificateNamespace, Name: certName}, stored)
	if client.IgnoreNotFound(err) != nil {
		return nil, fmt.Errorf("getting stored secret: %w", err)
	}
	if err != nil {
		stored = nil
	}

	var issuing corev1.Secret
	err = c.Get(ctx, types.NamespacedName{Namespace: r.CertificateNamespace, Name: issuingSecretName(certName)}, &issuing)
	if client.IgnoreNotFound(err) != nil {
		return nil, fmt.Errorf("getting issued secret: %w", err)
	}
	if err != nil {
		return stored, nil
	}
	candidate, ok := validIssued(&issuing, tc)
	if !ok {
		return stored, nil
	}
	if stored != nil {
		if equality.Semantic.DeepEqual(stored.Data, tlsData(&issuing)) {
			return stored, nil
		}
		if current, ok := validIssued(stored, tc); ok && !candidate.NotBefore.After(current.NotBefore) {
			return stored, nil
		}
	}

	next := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.CertificateNamespace,
			Name:      certName,
			Labels:    map[string]string{UpstreamUIDLabel: string(tc.UID)},
		},
		Type: corev1.SecretTypeTLS,
		Data: tlsData(&issuing),
	}
	if stored == nil {
		err = c.Create(ctx, next)
	} else {
		next.ResourceVersion = stored.ResourceVersion
		err = c.Update(ctx, next)
	}
	if err != nil {
		return nil, fmt.Errorf("storing issued certificate %s: %w", certName, err)
	}
	return next, nil
}

func validIssued(secret *corev1.Secret, tc *certificatesv1alpha1.TLSCertificate) (*x509.Certificate, bool) {
	if secret.Labels[UpstreamUIDLabel] != string(tc.UID) ||
		len(secret.Data[corev1.TLSCertKey]) == 0 || len(secret.Data[corev1.TLSPrivateKeyKey]) == 0 {
		return nil, false
	}
	if _, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey]); err != nil {
		return nil, false
	}
	leaf, err := parseLeaf(secret.Data[corev1.TLSCertKey])
	if err != nil || !sameNames(leaf.DNSNames, tc.Spec.DNSNames) {
		return nil, false
	}
	return leaf, true
}

func sameNames(sans []string, names []certificatesv1alpha1.DNSName) bool {
	want := make([]string, 0, len(names))
	for _, n := range names {
		want = append(want, string(n))
	}
	got := slices.Clone(sans)
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(slices.Compact(got), slices.Compact(want))
}

// syncProjectSecret copies the stored key pair into the project and reports
// readiness. It returns the leaf's expiry.
func (r *TLSCertificateReconciler) syncProjectSecret(
	ctx context.Context,
	cl cluster.Cluster,
	tc *certificatesv1alpha1.TLSCertificate,
	certName, secretName string,
) (*metav1.Time, error) {
	stored, err := r.storeIssued(ctx, tc, certName)
	if err != nil {
		return nil, err
	}
	if stored == nil || stored.Labels[UpstreamUIDLabel] != string(tc.UID) {
		r.setCondition(tc, certificatesv1alpha1.ConditionReady, metav1.ConditionFalse, "Pending", "The certificate has not been issued yet.")
		return nil, nil
	}
	issued := *stored

	leaf, err := parseLeaf(issued.Data[corev1.TLSCertKey])
	if err != nil {
		r.setCondition(tc, certificatesv1alpha1.ConditionReady, metav1.ConditionFalse, "InvalidCertificate", "The stored certificate could not be parsed.")
		return nil, nil
	}
	if missing := uncoveredNames(leaf, tc.Spec.DNSNames); len(missing) > 0 {
		r.setCondition(tc, certificatesv1alpha1.ConditionReady, metav1.ConditionFalse, "Pending",
			"The issued certificate does not cover "+strings.Join(missing, ", ")+".")
		return nil, nil
	}

	notBefore, notAfter := metav1.NewTime(leaf.NotBefore), metav1.NewTime(leaf.NotAfter)
	tc.Status.NotBefore, tc.Status.NotAfter = &notBefore, &notAfter
	tc.Status.ServiceSecretRef = &certificatesv1alpha1.ServiceSecretReference{Namespace: r.CertificateNamespace, Name: certName}

	if !time.Now().Before(leaf.NotAfter) {
		r.setCondition(tc, certificatesv1alpha1.ConditionReady, metav1.ConditionFalse, "Expired", "The certificate has expired.")
		return nil, nil
	}

	gvk := certificatesv1alpha1.GroupVersion.WithKind("TLSCertificate")
	secret := corev1ac.Secret(secretName, tc.Namespace).
		WithType(corev1.SecretTypeTLS).
		WithLabels(map[string]string{UpstreamUIDLabel: string(tc.UID)}).
		WithData(tlsData(&issued)).
		WithOwnerReferences(metav1ac.OwnerReference().
			WithAPIVersion(gvk.GroupVersion().String()).
			WithKind(gvk.Kind).
			WithName(tc.Name).
			WithUID(tc.UID).
			WithController(true).
			WithBlockOwnerDeletion(true))
	if err := cl.GetClient().Apply(ctx, secret, client.FieldOwner(fieldManager)); err != nil {
		if apierrors.IsInvalid(err) || apierrors.IsConflict(err) {
			r.setCondition(tc, certificatesv1alpha1.ConditionReady, metav1.ConditionFalse, "SecretConflict",
				fmt.Sprintf("Secret %q exists and is not managed by this TLSCertificate.", secretName))
			return &notAfter, nil
		}
		return nil, fmt.Errorf("applying project secret: %w", err)
	}

	r.setCondition(tc, certificatesv1alpha1.ConditionReady, metav1.ConditionTrue, "Issued",
		fmt.Sprintf("The certificate is stored in Secret %q.", secretName))
	return &notAfter, nil
}

func parseLeaf(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM certificate found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func uncoveredNames(leaf *x509.Certificate, names []certificatesv1alpha1.DNSName) []string {
	var missing []string
	for _, n := range names {
		if !slices.Contains(leaf.DNSNames, string(n)) {
			missing = append(missing, string(n))
		}
	}
	return missing
}

func tlsData(issued *corev1.Secret) map[string][]byte {
	data := map[string][]byte{
		corev1.TLSCertKey:       issued.Data[corev1.TLSCertKey],
		corev1.TLSPrivateKeyKey: issued.Data[corev1.TLSPrivateKeyKey],
	}
	if ca := issued.Data[cmmeta.TLSCAKey]; len(ca) > 0 {
		data[cmmeta.TLSCAKey] = ca
	}
	return data
}

// finalize removes the service-side resources. The project Secret carries a
// controller reference to the TLSCertificate, so garbage collection removes
// it; the service never deletes a project Secret it cannot prove it owns.
func (r *TLSCertificateReconciler) finalize(ctx context.Context, cl cluster.Cluster, clusterName multicluster.ClusterName, tc *certificatesv1alpha1.TLSCertificate, certName string) error {
	if !controllerutil.ContainsFinalizer(tc, tlsCertificateFinalizer) {
		return nil
	}
	if err := deleteServiceResources(ctx, r.mgr.GetLocalManager().GetClient(), r.CertificateNamespace, certName); err != nil {
		return err
	}

	base := tc.DeepCopy()
	controllerutil.RemoveFinalizer(tc, tlsCertificateFinalizer)
	if err := cl.GetClient().Patch(ctx, tc, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("removing finalizer: %w", err)
	}
	return nil
}

func deleteServiceResources(ctx context.Context, c client.Client, namespace, certName string) error {
	meta := metav1.ObjectMeta{Name: certName, Namespace: namespace}
	for _, obj := range []client.Object{
		&cmv1.Certificate{ObjectMeta: meta},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: issuingSecretName(certName), Namespace: namespace}},
		&corev1.Secret{ObjectMeta: meta},
		&corev1.ConfigMap{ObjectMeta: meta},
	} {
		if err := client.IgnoreNotFound(c.Delete(ctx, obj)); err != nil {
			return fmt.Errorf("deleting %T %s/%s: %w", obj, namespace, certName, err)
		}
	}
	return nil
}

func (r *TLSCertificateReconciler) setCondition(tc *certificatesv1alpha1.TLSCertificate, t string, status metav1.ConditionStatus, reason, msg string) {
	apimeta.SetStatusCondition(&tc.Status.Conditions, metav1.Condition{
		Type:               t,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: tc.Generation,
	})
}

func truncate(msg string) string {
	if len(msg) > maxConditionMessage {
		return msg[:maxConditionMessage]
	}
	return msg
}

func (r *TLSCertificateReconciler) resyncInterval() time.Duration {
	if r.ResyncInterval > 0 {
		return r.ResyncInterval
	}
	return defaultResyncInterval
}

func projectSecretName(tc *certificatesv1alpha1.TLSCertificate) string {
	if tc.Spec.SecretName != "" {
		return tc.Spec.SecretName
	}
	return tc.Name + "-tls"
}

func serviceCertificateName(clusterName multicluster.ClusterName, namespace, name string, uid types.UID) string {
	sum := sha256.Sum256([]byte(string(clusterName) + "/" + namespace + "/" + name + "/" + string(uid)))
	return "tc-" + hex.EncodeToString(sum[:16])
}

// issuingSecretName names the Secret cert-manager writes for certName. The
// service copies it into a Secret named certName that it owns.
func issuingSecretName(certName string) string {
	return certName + issuingSecretSuffix
}

func clusterLabel(clusterName multicluster.ClusterName) string {
	return "cluster-" + strings.ReplaceAll(string(clusterName), "/", "_")
}

func serviceLabels(clusterName multicluster.ClusterName, tc *certificatesv1alpha1.TLSCertificate) map[string]string {
	return map[string]string{
		downstreamclient.UpstreamOwnerClusterNameLabel: clusterLabel(clusterName),
		downstreamclient.UpstreamOwnerGroupLabel:       certificatesv1alpha1.GroupVersion.Group,
		downstreamclient.UpstreamOwnerKindLabel:        "TLSCertificate",
		downstreamclient.UpstreamOwnerNameLabel:        tc.Name,
		downstreamclient.UpstreamOwnerNamespaceLabel:   tc.Namespace,
		UpstreamUIDLabel: string(tc.UID),
	}
}

// SetupWithManager registers the reconciler, watching TLSCertificates in every
// engaged project control plane and the cert-manager resources that back them
// on the local cluster.
func (r *TLSCertificateReconciler) SetupWithManager(mgr mcmanager.Manager) error {
	r.mgr = mgr
	local := mgr.GetLocalManager()

	workers := r.MaxConcurrentReconciles
	if workers <= 0 {
		workers = defaultMaxConcurrentReconciles
	}

	return mcbuilder.ControllerManagedBy(mgr).
		For(&certificatesv1alpha1.TLSCertificate{}).
		WithOptions(controller.TypedOptions[mcreconcile.Request]{MaxConcurrentReconciles: workers}).
		WatchesRawSource(milosource.MustNewClusterSource(
			local,
			&cmv1.Certificate{},
			downstreamclient.TypedEnqueueRequestsForUpstreamOwner[*cmv1.Certificate](&certificatesv1alpha1.TLSCertificate{}),
		)).
		WatchesRawSource(milosource.MustNewClusterSource(
			local,
			&corev1.Secret{},
			enqueueForCertificateOf(func(_ context.Context, _ client.Client, s *corev1.Secret) string {
				if s.Labels[UpstreamUIDLabel] == "" {
					return ""
				}
				return strings.TrimSuffix(s.Name, issuingSecretSuffix)
			}),
		)).
		WatchesRawSource(milosource.MustNewClusterSource(
			local,
			&acmev1.Order{},
			enqueueForCertificateOf(func(_ context.Context, _ client.Client, o *acmev1.Order) string {
				return o.Annotations[cmv1.CertificateNameKey]
			}),
		)).
		WatchesRawSource(milosource.MustNewClusterSource(
			local,
			&acmev1.Challenge{},
			enqueueForCertificateOf(func(ctx context.Context, c client.Client, ch *acmev1.Challenge) string {
				owner := metav1.GetControllerOf(ch)
				if owner == nil || owner.Kind != "Order" {
					return ""
				}
				var order acmev1.Order
				if err := c.Get(ctx, types.NamespacedName{Namespace: ch.Namespace, Name: owner.Name}, &order); err != nil {
					return ""
				}
				return order.Annotations[cmv1.CertificateNameKey]
			}),
		)).
		Named("tlscertificate").
		Complete(r)
}

// enqueueForCertificateOf maps a local object to the TLSCertificate that owns
// the named service-side resource, reading the upstream labels from the
// Certificate or, when renewal is suspended, the delegation anchor.
func enqueueForCertificateOf[T client.Object](certificateName func(context.Context, client.Client, T) string) mchandler.TypedEventHandlerFunc[T, mcreconcile.Request] {
	return func(_ multicluster.ClusterName, cl cluster.Cluster) handler.TypedEventHandler[T, mcreconcile.Request] {
		return handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, obj T) []mcreconcile.Request {
			name := certificateName(ctx, cl.GetClient(), obj)
			if name == "" {
				return nil
			}
			key := types.NamespacedName{Namespace: obj.GetNamespace(), Name: name}
			var cert cmv1.Certificate
			if err := cl.GetClient().Get(ctx, key, &cert); err == nil {
				if req, ok := upstreamRequest(cert.Labels); ok {
					return []mcreconcile.Request{req}
				}
			}
			var anchor corev1.ConfigMap
			if err := cl.GetClient().Get(ctx, key, &anchor); err == nil {
				if req, ok := upstreamRequest(anchor.Labels); ok {
					return []mcreconcile.Request{req}
				}
			}
			return nil
		})
	}
}

func upstreamRequest(labels map[string]string) (mcreconcile.Request, bool) {
	if labels[downstreamclient.UpstreamOwnerGroupLabel] != certificatesv1alpha1.GroupVersion.Group ||
		labels[downstreamclient.UpstreamOwnerKindLabel] != "TLSCertificate" {
		return mcreconcile.Request{}, false
	}
	clusterName := strings.TrimPrefix(strings.ReplaceAll(labels[downstreamclient.UpstreamOwnerClusterNameLabel], "_", "/"), "cluster-")
	return mcreconcile.Request{
		ClusterName: multicluster.ClusterName(clusterName),
		Request: reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: labels[downstreamclient.UpstreamOwnerNamespaceLabel],
			Name:      labels[downstreamclient.UpstreamOwnerNameLabel],
		}},
	}, true
}
