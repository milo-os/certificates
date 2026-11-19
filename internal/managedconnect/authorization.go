package managedconnect

import (
	"context"
	"errors"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certificates "go.miloapis.com/certificates/api/v1alpha1"
	"go.miloapis.com/certificates/internal/validation"
)

var EndpointGVK = schema.GroupVersionKind{Group: "connect.datumapis.com", Version: "v1alpha1", Kind: "ConnectEndpoint"}

type Authorizer struct {
	Reader           client.Reader
	ClusterName      string
	Namespace        string
	DomainSuffix     string
	DelegationZone   string
	WriterIdentities []string
}

func (a *Authorizer) Verify(ctx context.Context, tc *certificates.TLSCertificate, clusterName string, requireUID bool) error {
	if a == nil || a.Reader == nil || a.ClusterName == "" || a.Namespace == "" || a.DomainSuffix == "" {
		return errors.New("managed Connect issuance is disabled")
	}
	if clusterName != a.ClusterName || tc.Namespace != a.Namespace {
		return errors.New("managed certificate must belong to the configured Connect project and namespace")
	}
	ref := tc.Spec.ManagedAuthorization
	if ref == nil || ref.ReservationName == "" || ref.ReservationUID == "" {
		return errors.New("managed certificate requires a reservation name and UID")
	}
	if tc.Spec.Issuance != certificates.IssuanceModeDNS01 || len(tc.Spec.DNSNames) != 1 {
		return errors.New("managed certificate requires explicit DNS01 and exactly one hostname")
	}
	hostname := string(tc.Spec.DNSNames[0])
	if validation.IsWildcard(hostname) || !strings.HasSuffix(hostname, "."+a.DomainSuffix) || validation.IsDenied(hostname, []string{a.DelegationZone}) {
		return errors.New("hostname is outside the managed Connect issuance boundary")
	}
	endpoint := &unstructured.Unstructured{}
	endpoint.SetGroupVersionKind(EndpointGVK)
	if err := a.Reader.Get(ctx, client.ObjectKey{Namespace: a.Namespace, Name: ref.ReservationName}, endpoint); err != nil {
		return errors.New("managed Connect reservation could not be read; retry after its API is available")
	}
	if string(endpoint.GetUID()) != ref.ReservationUID || !endpoint.GetDeletionTimestamp().IsZero() {
		return errors.New("managed Connect reservation identity is invalid or deleting")
	}
	for _, key := range []string{"customerProjectUID", "gatewayUID", "metro"} {
		if value(endpoint, "spec", key) == "" {
			return errors.New("managed Connect reservation ownership tuple is incomplete")
		}
	}
	if value(endpoint, "spec", "hostname") != hostname || value(endpoint, "spec", "lifecycle") != "Active" || value(endpoint, "status", "phase") != "Active" || value(endpoint, "status", "certificateRef", "name") != tc.Name {
		return errors.New("managed Connect reservation does not authorize this certificate")
	}
	boundUID := value(endpoint, "status", "certificateRef", "uid")
	if requireUID && (tc.UID == "" || boundUID != string(tc.UID)) {
		return errors.New("managed Connect reservation is awaiting the exact certificate UID binding")
	}
	if !requireUID && boundUID != "" && boundUID != string(tc.UID) {
		return errors.New("managed Connect reservation is bound to another certificate")
	}
	return nil
}

func value(object *unstructured.Unstructured, fields ...string) string {
	value, _, _ := unstructured.NestedString(object.Object, fields...)
	return value
}
