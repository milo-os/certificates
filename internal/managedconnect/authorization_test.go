package managedconnect

import (
	"context"
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	certificates "go.miloapis.com/certificates/api/v1alpha1"
)

func reservation() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": EndpointGVK.GroupVersion().String(), "kind": EndpointGVK.Kind,
		"metadata": map[string]interface{}{"name": "endpoint", "namespace": "connect", "uid": "reservation-uid"},
		"spec":     map[string]interface{}{"customerProjectUID": "customer-uid", "gatewayUID": "gateway-uid", "metro": "dfw", "hostname": "opaque.connect.example.com", "lifecycle": "Active"},
		"status":   map[string]interface{}{"certificateRef": map[string]interface{}{"name": "endpoint", "uid": "certificate-uid"}},
	}}
}

func certificate() *certificates.TLSCertificate {
	return &certificates.TLSCertificate{
		ObjectMeta: metav1.ObjectMeta{Name: "endpoint", Namespace: "connect", UID: "certificate-uid"},
		Spec: certificates.TLSCertificateSpec{DNSNames: []certificates.DNSName{"opaque.connect.example.com"}, Issuance: certificates.IssuanceModeDNS01,
			ManagedAuthorization: &certificates.ManagedAuthorization{ReservationName: "endpoint", ReservationUID: "reservation-uid"}},
	}
}

func TestReservationAuthorization(t *testing.T) {
	tests := []struct {
		name   string
		change func(*certificates.TLSCertificate, *unstructured.Unstructured, *Authorizer)
	}{
		{"wrong reservation UID", func(tc *certificates.TLSCertificate, _ *unstructured.Unstructured, _ *Authorizer) {
			tc.Spec.ManagedAuthorization.ReservationUID = "other"
		}},
		{"missing reservation", func(tc *certificates.TLSCertificate, _ *unstructured.Unstructured, _ *Authorizer) {
			tc.Spec.ManagedAuthorization.ReservationName = "absent"
		}},
		{"no capability", func(tc *certificates.TLSCertificate, _ *unstructured.Unstructured, _ *Authorizer) {
			tc.Spec.ManagedAuthorization = nil
		}},
		{"different namespace", func(tc *certificates.TLSCertificate, _ *unstructured.Unstructured, _ *Authorizer) {
			tc.Namespace = "tenant"
		}},
		{"deleting reservation", func(_ *certificates.TLSCertificate, endpoint *unstructured.Unstructured, _ *Authorizer) {
			now := metav1.Now()
			endpoint.SetDeletionTimestamp(&now)
			endpoint.SetFinalizers([]string{"connect.datumapis.com/cleanup"})
		}},
		{"unbound UID", func(_ *certificates.TLSCertificate, ep *unstructured.Unstructured, _ *Authorizer) {
			unstructured.RemoveNestedField(ep.Object, "status", "certificateRef", "uid")
		}},
		{"recreated certificate", func(tc *certificates.TLSCertificate, _ *unstructured.Unstructured, _ *Authorizer) {
			tc.UID = "replacement"
		}},
		{"different certificate name", func(tc *certificates.TLSCertificate, _ *unstructured.Unstructured, _ *Authorizer) {
			tc.Name = "another"
		}},
		{"wrong hostname", func(tc *certificates.TLSCertificate, _ *unstructured.Unstructured, _ *Authorizer) {
			tc.Spec.DNSNames[0] = "another.connect.example.com"
		}},
		{"wildcard", func(tc *certificates.TLSCertificate, _ *unstructured.Unstructured, _ *Authorizer) {
			tc.Spec.DNSNames[0] = "*.connect.example.com"
		}},
		{"extra SAN", func(tc *certificates.TLSCertificate, _ *unstructured.Unstructured, _ *Authorizer) {
			tc.Spec.DNSNames = append(tc.Spec.DNSNames, "extra.connect.example.com")
		}},
		{"Auto mode", func(tc *certificates.TLSCertificate, _ *unstructured.Unstructured, _ *Authorizer) {
			tc.Spec.Issuance = certificates.IssuanceModeAuto
		}},
		{"HTTP01 mode", func(tc *certificates.TLSCertificate, _ *unstructured.Unstructured, _ *Authorizer) {
			tc.Spec.Issuance = certificates.IssuanceModeHTTP01
		}},
		{"delegation zone", func(_ *certificates.TLSCertificate, _ *unstructured.Unstructured, auth *Authorizer) {
			auth.DelegationZone = "connect.example.com"
		}},
		{"outside boundary", func(_ *certificates.TLSCertificate, _ *unstructured.Unstructured, auth *Authorizer) {
			auth.DomainSuffix = "other.example.com"
		}},
		{"wrong project", func(_ *certificates.TLSCertificate, _ *unstructured.Unstructured, auth *Authorizer) {
			auth.ClusterName = "another-project"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tc, endpoint := certificate(), reservation()
			auth := &Authorizer{Namespace: "connect", ClusterName: "service-project", DomainSuffix: "connect.example.com"}
			test.change(tc, endpoint, auth)
			auth.Reader = fake.NewClientBuilder().WithScheme(runtime.NewScheme()).WithObjects(endpoint).Build()
			if err := auth.Verify(context.Background(), tc, "service-project", true); err == nil {
				t.Fatal("unauthorized certificate was accepted")
			}
		})
	}
	for _, fields := range [][]string{{"spec", "customerProjectUID"}, {"spec", "gatewayUID"}, {"spec", "metro"}, {"spec", "lifecycle"}} {
		t.Run(strings.Join(fields, "."), func(t *testing.T) {
			for _, replacement := range []string{"", "Deleting", "Retired"} {
				endpoint := reservation()
				if fields[1] == "lifecycle" || replacement == "" {
					_ = unstructured.SetNestedField(endpoint.Object, replacement, fields...)
					auth := &Authorizer{Namespace: "connect", ClusterName: "service-project", DomainSuffix: "connect.example.com", Reader: fake.NewClientBuilder().WithObjects(endpoint).Build()}
					if err := auth.Verify(context.Background(), certificate(), "service-project", true); err == nil {
						t.Fatal("incomplete or inactive reservation authorized")
					}
				}
			}
		})
	}
}

func TestLifecycleAuthorizationIgnoresLegacyPhaseAndReadiness(t *testing.T) {
	for _, lifecycle := range []string{"Active", "Deleting", "Retired", "", "Unknown", "absent"} {
		for _, phase := range []string{"absent", "Active", "Deleting", "Retired"} {
			t.Run(lifecycle+"/"+phase, func(t *testing.T) {
				endpoint := reservation()
				if lifecycle == "absent" {
					unstructured.RemoveNestedField(endpoint.Object, "spec", "lifecycle")
				} else if err := unstructured.SetNestedField(endpoint.Object, lifecycle, "spec", "lifecycle"); err != nil {
					t.Fatal(err)
				}
				if phase != "absent" {
					if err := unstructured.SetNestedField(endpoint.Object, phase, "status", "phase"); err != nil {
						t.Fatal(err)
					}
				}
				conditions := []interface{}{map[string]interface{}{"type": "Ready", "status": "False", "reason": "CertificatePending"}}
				if err := unstructured.SetNestedSlice(endpoint.Object, conditions, "status", "conditions"); err != nil {
					t.Fatal(err)
				}
				auth := &Authorizer{Namespace: "connect", ClusterName: "service-project", DomainSuffix: "connect.example.com", Reader: fake.NewClientBuilder().WithObjects(endpoint).Build()}
				for _, requireUID := range []bool{false, true} {
					err := auth.Verify(context.Background(), certificate(), "service-project", requireUID)
					if (err == nil) != (lifecycle == "Active") {
						t.Fatalf("unexpected authorization (requireUID=%t): %v", requireUID, err)
					}
				}
			})
		}
	}
}

type failingReader struct{ client.Reader }

func (f failingReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("transport failure containing SECRET_BYTES")
}

func TestReservationBootstrapRetryAndReadFailure(t *testing.T) {
	endpoint, tc := reservation(), certificate()
	unstructured.RemoveNestedField(endpoint.Object, "status", "certificateRef", "uid")
	reader := fake.NewClientBuilder().WithObjects(endpoint).Build()
	auth := &Authorizer{Reader: reader, Namespace: "connect", ClusterName: "service-project", DomainSuffix: "connect.example.com"}
	tc.UID = ""
	if err := auth.Verify(context.Background(), tc, "service-project", false); err != nil {
		t.Fatal(err)
	}
	tc.UID = "certificate-uid"
	if err := auth.Verify(context.Background(), tc, "service-project", true); err == nil {
		t.Fatal("issued before binding")
	}
	_ = unstructured.SetNestedField(endpoint.Object, string(tc.UID), "status", "certificateRef", "uid")
	if err := reader.Update(context.Background(), endpoint); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := auth.Verify(context.Background(), tc, "service-project", true); err != nil {
			t.Fatal(err)
		}
	}
	auth.Reader = failingReader{}
	if err := auth.Verify(context.Background(), tc, "service-project", true); err == nil || strings.Contains(err.Error(), "SECRET_BYTES") {
		t.Fatalf("unsafe read failure: %v", err)
	}
	auth.Reader = reader
	if err := auth.Verify(context.Background(), tc, "service-project", true); err != nil {
		t.Fatal(err)
	}
	var disabled *Authorizer
	if err := disabled.Verify(context.Background(), tc, "service-project", true); err == nil {
		t.Fatal("disabled authorization accepted")
	}
}
