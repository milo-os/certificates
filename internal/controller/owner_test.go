// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"testing"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"go.miloapis.com/milo/pkg/downstreamclient"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"
)

func ownerLabels(name string) map[string]string {
	return map[string]string{
		downstreamclient.UpstreamOwnerClusterNameLabel: "cluster-project-x",
		downstreamclient.UpstreamOwnerGroupLabel:       certificatesv1alpha1.GroupVersion.Group,
		downstreamclient.UpstreamOwnerKindLabel:        "TLSCertificate",
		downstreamclient.UpstreamOwnerNameLabel:        name,
		downstreamclient.UpstreamOwnerNamespaceLabel:   "ns",
	}
}

func TestOwnerOfReadsCertificatesAndAnchorsFromTheirOwnClusters(t *testing.T) {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(cmv1.AddToScheme(s))
	key := types.NamespacedName{Namespace: "certificates-system", Name: "tc-abc"}
	meta := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, Labels: ownerLabels(name)}
	}

	tests := []struct {
		name        string
		certManager []client.Object
		local       []client.Object
		want        string
	}{
		{
			name:        "certificate on the cert-manager cluster",
			certManager: []client.Object{&cmv1.Certificate{ObjectMeta: meta("from-certificate")}},
			local:       []client.Object{&corev1.ConfigMap{ObjectMeta: meta("from-anchor")}},
			want:        "from-certificate",
		},
		{
			name:  "suspended certificate falls back to the local anchor",
			local: []client.Object{&corev1.ConfigMap{ObjectMeta: meta("from-anchor")}},
			want:  "from-anchor",
		},
		{
			name:        "anchor on the cert-manager cluster is ignored",
			certManager: []client.Object{&corev1.ConfigMap{ObjectMeta: meta("wrong-cluster")}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certManager := fake.NewClientBuilder().WithScheme(s).WithObjects(tt.certManager...).Build()
			local := fake.NewClientBuilder().WithScheme(s).WithObjects(tt.local...).Build()
			req, ok := ownerOf(context.Background(), certManager, local, key)
			if tt.want == "" {
				if ok {
					t.Fatalf("expected no owner, got %v", req)
				}
				return
			}
			if !ok || req.Name != tt.want || req.Namespace != "ns" || req.ClusterName != "project-x" {
				t.Fatalf("got %v (ok=%v), want %s", req, ok, tt.want)
			}
		})
	}
}
