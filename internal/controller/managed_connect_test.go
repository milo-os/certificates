package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	certificates "go.miloapis.com/certificates/api/v1alpha1"
	"go.miloapis.com/certificates/internal/managedconnect"
)

func TestManagedAuthorizationReconcileRetryAndSuspension(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := errors.Join(corev1.AddToScheme(scheme), cmv1.AddToScheme(scheme), acmev1.AddToScheme(scheme)); err != nil {
		t.Fatal(err)
	}
	serviceClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	projectClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "connect", UID: "namespace-uid"}}).Build()
	endpoint := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "connect.datumapis.com/v1alpha1", "kind": "ConnectEndpoint",
		"metadata": map[string]interface{}{"name": "endpoint", "namespace": "connect", "uid": "reservation-uid"},
		"spec":     map[string]interface{}{"customerProjectUID": "customer", "gatewayUID": "gateway", "metro": "dfw", "hostname": "opaque.connect.datum.net", "lifecycle": "Active"},
		"status":   map[string]interface{}{"phase": "Active", "certificateRef": map[string]interface{}{"name": "endpoint"}},
	}}
	unavailable := false
	reservationClient := fake.NewClientBuilder().WithObjects(endpoint).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
			if unavailable {
				return errors.New("private transport failure")
			}
			return delegate.Get(ctx, key, object, opts...)
		},
	}).Build()
	tc := &certificates.TLSCertificate{ObjectMeta: metav1.ObjectMeta{Name: "endpoint", Namespace: "connect", UID: "certificate-uid"},
		Spec: certificates.TLSCertificateSpec{DNSNames: []certificates.DNSName{"opaque.connect.datum.net"}, Issuance: certificates.IssuanceModeDNS01, ManagedAuthorization: &certificates.ManagedAuthorization{ReservationName: "endpoint", ReservationUID: "reservation-uid"}},
	}
	resolver := &fakeResolver{records: map[string]string{}, transient: map[string]bool{}}
	reconciler := &TLSCertificateReconciler{
		mgr:                  localOnlyManager{local: clientOnlyManager{client: serviceClient}},
		CertificateNamespace: "certificates-system", DNS01ClusterIssuer: "dns01", DNS01DelegationZone: "acme.example.net",
		DeniedDomainSuffixes: []string{"datum.net"}, Resolver: resolver,
		ManagedConnect: &managedconnect.Authorizer{Reader: reservationClient, ClusterName: "service-project", Namespace: "connect", DomainSuffix: "connect.datum.net"},
	}
	name := certificates.StoredSecretName(tc.UID)
	reconcile := func() {
		t.Helper()
		result, err := reconciler.computeStatus(ctx, clientOnlyManager{client: projectClient}, "service-project", tc, name)
		if err != nil {
			t.Fatal(err)
		}
		if result.RequeueAfter <= 0 || result.RequeueAfter > time.Minute {
			t.Fatalf("authorization not retried promptly: %v", result)
		}
	}
	assertSuspended := func() {
		t.Helper()
		if accepted := condition(tc, certificates.ConditionAccepted); accepted == nil || accepted.Status != metav1.ConditionFalse {
			t.Fatalf("expected rejection: %+v", tc.Status)
		}
		if err := serviceClient.Get(ctx, client.ObjectKey{Namespace: reconciler.CertificateNamespace, Name: name}, &cmv1.Certificate{}); !apierrors.IsNotFound(err) {
			t.Fatalf("issuance not suspended: %v", err)
		}
	}
	reconcile()
	assertSuspended()
	if err := unstructured.SetNestedField(endpoint.Object, string(tc.UID), "status", "certificateRef", "uid"); err != nil {
		t.Fatal(err)
	}
	if err := reservationClient.Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if len(tc.Status.RequiredDNSRecords) != 1 {
		t.Fatalf("no exact delegation CNAME: %+v", tc.Status)
	}
	record := tc.Status.RequiredDNSRecords[0]
	if record.Type != "CNAME" || record.Name != "_acme-challenge.opaque.connect.datum.net" {
		t.Fatalf("unexpected delegation: %+v", record)
	}
	resolver.set(record.Name, record.Content)
	for range 3 {
		reconcile()
	}
	var issued cmv1.Certificate
	if err := serviceClient.Get(ctx, client.ObjectKey{Namespace: reconciler.CertificateNamespace, Name: name}, &issued); err != nil {
		t.Fatal(err)
	}
	if issued.Spec.IssuerRef.Name != "dns01" || issued.Spec.SecretName != name+"-issuing" || issued.Labels[UpstreamUIDLabel] != string(tc.UID) {
		t.Fatalf("issuance consumer contract broken: %+v", issued.Spec)
	}
	stored := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: reconciler.CertificateNamespace, Labels: map[string]string{UpstreamUIDLabel: string(tc.UID)}}, Data: map[string][]byte{corev1.TLSPrivateKeyKey: []byte("retain-during-suspension")}}
	if err := serviceClient.Create(ctx, stored); err != nil {
		t.Fatal(err)
	}
	unavailable = true
	reconcile()
	assertSuspended()
	unavailable = false
	reconcile()
	if err := serviceClient.Get(ctx, client.ObjectKeyFromObject(&issued), &issued); err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedField(endpoint.Object, "Deleting", "spec", "lifecycle"); err != nil {
		t.Fatal(err)
	}
	if err := reservationClient.Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	reconcile()
	assertSuspended()
	if err := serviceClient.Get(ctx, client.ObjectKeyFromObject(stored), stored); err != nil {
		t.Fatal("suspension deleted stored key")
	}
	var projectSecrets corev1.SecretList
	if err := projectClient.List(ctx, &projectSecrets); err != nil || len(projectSecrets.Items) != 0 {
		t.Fatalf("project received secrets: %v", err)
	}
}
