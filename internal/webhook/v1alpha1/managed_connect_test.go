package webhook

import (
	"context"
	"testing"

	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	certificates "go.miloapis.com/certificates/api/v1alpha1"
	"go.miloapis.com/certificates/internal/managedconnect"
)

const connectWriter = "system:managed-endpoints@connect.datumapis.com"

func managedRequest(username, project string) context.Context {
	return admission.NewContextWithRequest(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UserInfo: authenticationv1.UserInfo{Username: username, Extra: map[string]authenticationv1.ExtraValue{
			iam.ParentKindExtraKey: {"Project"}, iam.ParentNameExtraKey: {project},
		}},
	}})
}

func managedValidator() *Validator {
	endpoint := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "connect.datumapis.com/v1alpha1", "kind": "ConnectEndpoint",
		"metadata": map[string]interface{}{"name": "endpoint", "namespace": "default", "uid": "reservation-uid"},
		"spec":     map[string]interface{}{"customerProjectUID": "customer", "gatewayUID": "gateway", "metro": "dfw", "hostname": "opaque.connect.datum.net", "lifecycle": "Active"},
		"status":   map[string]interface{}{"certificateRef": map[string]interface{}{"name": "web"}},
	}}
	return &Validator{
		DeniedDomainSuffixes: []string{"datum.net"},
		ManagedConnect:       &managedconnect.Authorizer{Reader: fake.NewClientBuilder().WithObjects(endpoint).Build(), ClusterName: "service-project", Namespace: "default", DomainSuffix: "connect.datum.net", DelegationZone: "acme.datum.net", WriterIdentities: []string{connectWriter}},
	}
}

func TestManagedAdmissionIdentityAndProject(t *testing.T) {
	validator := managedValidator()
	tc := tlsCertificate(certificates.IssuanceModeDNS01, "opaque.connect.datum.net")
	tc.Spec.ManagedAuthorization = &certificates.ManagedAuthorization{ReservationName: "endpoint", ReservationUID: "reservation-uid"}
	if _, err := validator.ValidateCreate(managedRequest(connectWriter, "service-project"), tc); err != nil {
		t.Fatal(err)
	}
	statusRequest, err := admission.RequestFromContext(managedRequest(connectWriter, "service-project"))
	if err != nil {
		t.Fatal(err)
	}
	statusRequest.SubResource = "status"
	if _, err := validator.ValidateUpdate(admission.NewContextWithRequest(context.Background(), statusRequest), tc, tc.DeepCopy()); err == nil {
		t.Fatal("Connect writer was allowed to forge certificate status")
	}
	for _, request := range []context.Context{
		managedRequest(tenant, "service-project"), managedRequest(writer, "service-project"),
		managedRequest(connectWriter, "customer-project"), requestContext(connectWriter, ""),
	} {
		if _, err := validator.ValidateCreate(request, tc); err == nil {
			t.Fatal("untrusted identity or project accepted with ordinary writer checking disabled")
		}
	}
	ordinary := tc.DeepCopy()
	ordinary.Spec.ManagedAuthorization = nil
	ordinary.Annotations = map[string]string{"managed-connect-authorized": "true"}
	if _, err := validator.ValidateCreate(managedRequest(connectWriter, "service-project"), ordinary); err == nil {
		t.Fatal("annotations or service project alone bypassed protection")
	}
	ordinary.Spec.DNSNames = []certificates.DNSName{"normal.example.com"}
	if _, err := validator.ValidateCreate(requestContext(tenant, ""), ordinary); err != nil {
		t.Fatalf("ordinary compatibility: %v", err)
	}
	validator.WriterIdentities = []string{writer}
	if _, err := validator.ValidateCreate(managedRequest(connectWriter, "service-project"), tc); err != nil {
		t.Fatal(err)
	}
	validator.ManagedConnect.Reader = nil
	if _, err := validator.ValidateDelete(managedRequest(connectWriter, "service-project"), tc); err != nil {
		t.Fatal(err)
	}
	updated := tc.DeepCopy()
	updated.Finalizers = []string{"test"}
	if _, err := validator.ValidateUpdate(managedRequest(connectWriter, "service-project"), tc, updated); err != nil {
		t.Fatal(err)
	}
	updated.Spec.ManagedAuthorization.ReservationUID = "new"
	if _, err := validator.ValidateUpdate(managedRequest(connectWriter, "service-project"), tc, updated); err == nil {
		t.Fatal("mutable reservation capability")
	}
	updated.Spec.ManagedAuthorization = nil
	if _, err := validator.ValidateUpdate(managedRequest(connectWriter, "service-project"), tc, updated); err == nil {
		t.Fatal("removed reservation capability")
	}
}

func TestManagedBoundaryAlwaysDeniesDelegationAndOrdinaryCallers(t *testing.T) {
	validator := managedValidator()
	validator.DeniedDomainSuffixes = nil
	tc := tlsCertificate(certificates.IssuanceModeDNS01, "opaque.connect.datum.net")
	if _, err := validator.ValidateCreate(managedRequest(connectWriter, "service-project"), tc); err == nil {
		t.Fatal("managed suffix not automatically protected")
	}
	tc.Spec.ManagedAuthorization = &certificates.ManagedAuthorization{ReservationName: "endpoint", ReservationUID: "reservation-uid"}
	validator.ManagedConnect.DelegationZone = "connect.datum.net"
	if _, err := validator.ValidateCreate(managedRequest(connectWriter, "service-project"), tc); err == nil {
		t.Fatal("delegation zone bypassed")
	}
	validator.ManagedConnect = nil
	if _, err := validator.ValidateCreate(managedRequest(connectWriter, "service-project"), tc); err == nil {
		t.Fatal("disabled managed issuance bypassed")
	}
}
