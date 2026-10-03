// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"regexp"
	"time"

	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"go.miloapis.com/milo/pkg/downstreamclient"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/multicluster-runtime/pkg/multicluster"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func newProjectNamespace(c client.Client) string {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "project-"}}
	Expect(c.Create(ctx, ns)).To(Succeed())
	return ns.Name
}

func newTLSCertificate(namespace, name string, issuance certificatesv1alpha1.IssuanceMode, names ...certificatesv1alpha1.DNSName) *certificatesv1alpha1.TLSCertificate {
	return &certificatesv1alpha1.TLSCertificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: certificatesv1alpha1.TLSCertificateSpec{
			DNSNames: names,
			Issuance: issuance,
		},
	}
}

func condition(tc *certificatesv1alpha1.TLSCertificate, t string) *metav1.Condition {
	return apimeta.FindStatusCondition(tc.Status.Conditions, t)
}

func getFrom(c client.Client, tc *certificatesv1alpha1.TLSCertificate) func(Gomega) *certificatesv1alpha1.TLSCertificate {
	return func(g Gomega) *certificatesv1alpha1.TLSCertificate {
		var out certificatesv1alpha1.TLSCertificate
		g.Expect(c.Get(ctx, client.ObjectKeyFromObject(tc), &out)).To(Succeed())
		return &out
	}
}

func get(tc *certificatesv1alpha1.TLSCertificate) func(Gomega) *certificatesv1alpha1.TLSCertificate {
	return getFrom(k8sClient, tc)
}

func hasCondition(t string, status metav1.ConditionStatus, reason string) OmegaMatcher {
	return WithTransform(func(tc *certificatesv1alpha1.TLSCertificate) *metav1.Condition {
		return condition(tc, t)
	}, And(Not(BeNil()), HaveField("Status", status), HaveField("Reason", reason)))
}

func certNameFor(cluster string, tc *certificatesv1alpha1.TLSCertificate) string {
	return serviceCertificateName(multicluster.ClusterName(cluster), tc.Namespace, tc.Name, tc.UID)
}

func selfSignedPEM(notAfter time.Time, names ...string) ([]byte, []byte) {
	return selfSignedPEMAt(time.Now().Add(-time.Hour), notAfter, names...)
}

func selfSignedPEMAt(notBefore, notAfter time.Time, names ...string) ([]byte, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		DNSNames:     names,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	keyDER, err := x509.MarshalECPrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func issueSecret(certName string, uid types.UID, names ...string) []byte {
	crt, key := selfSignedPEM(time.Now().Add(90*24*time.Hour), names...)
	Expect(k8sClient.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: serviceNamespace,
			Name:      issuingSecretName(certName),
			Labels:    map[string]string{UpstreamUIDLabel: string(uid)},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{corev1.TLSCertKey: crt, corev1.TLSPrivateKeyKey: key},
	})).To(Succeed())
	return crt
}

func serviceCertificateExists(certName string) func() bool {
	return func() bool {
		return k8sClient.Get(ctx, types.NamespacedName{Namespace: serviceNamespace, Name: certName}, &cmv1.Certificate{}) == nil
	}
}

func projectSecret(c client.Client, namespace, name string) func() error {
	return func() error {
		return c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &corev1.Secret{})
	}
}

var _ = Describe("TLSCertificate API validation", func() {
	var ns string
	BeforeEach(func() { ns = newProjectNamespace(k8sClient) })

	DescribeTable("rejects invalid specs",
		func(issuance certificatesv1alpha1.IssuanceMode, names []certificatesv1alpha1.DNSName) {
			err := k8sClient.Create(ctx, newTLSCertificate(ns, "invalid", issuance, names...))
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected invalid, got %v", err)
		},
		Entry("wildcard with HTTP01", certificatesv1alpha1.IssuanceModeHTTP01, []certificatesv1alpha1.DNSName{"*.example.com"}),
		Entry("star outside the leading label", certificatesv1alpha1.IssuanceModeAuto, []certificatesv1alpha1.DNSName{"a.*.example.com"}),
		Entry("double wildcard", certificatesv1alpha1.IssuanceModeDNS01, []certificatesv1alpha1.DNSName{"*.*.example.com"}),
		Entry("wildcard over a single label", certificatesv1alpha1.IssuanceModeDNS01, []certificatesv1alpha1.DNSName{"*.com"}),
		Entry("single label", certificatesv1alpha1.IssuanceModeAuto, []certificatesv1alpha1.DNSName{"localhost"}),
		Entry("label over 63 characters", certificatesv1alpha1.IssuanceModeAuto, []certificatesv1alpha1.DNSName{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
		}),
		Entry("IP address", certificatesv1alpha1.IssuanceModeAuto, []certificatesv1alpha1.DNSName{"1.2.3.4"}),
		Entry("uppercase", certificatesv1alpha1.IssuanceModeAuto, []certificatesv1alpha1.DNSName{"App.example.com"}),
		Entry("no names", certificatesv1alpha1.IssuanceModeAuto, []certificatesv1alpha1.DNSName{}),
		Entry("more than eight names", certificatesv1alpha1.IssuanceModeAuto, []certificatesv1alpha1.DNSName{
			"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com",
			"f.example.com", "g.example.com", "h.example.com", "i.example.com",
		}),
	)

	It("defaults issuance to Auto and keeps dnsNames and issuance immutable", func() {
		tc := newTLSCertificate(ns, "immutable", "", "app.example.com")
		Expect(k8sClient.Create(ctx, tc)).To(Succeed())
		Expect(tc.Spec.Issuance).To(Equal(certificatesv1alpha1.IssuanceModeAuto))

		Eventually(func() bool {
			changed := getFrom(k8sClient, tc)(Default)
			changed.Spec.DNSNames = []certificatesv1alpha1.DNSName{"other.example.com"}
			return apierrors.IsInvalid(k8sClient.Update(ctx, changed))
		}).Should(BeTrue())

		Eventually(func() bool {
			changed := getFrom(k8sClient, tc)(Default)
			changed.Spec.Issuance = certificatesv1alpha1.IssuanceModeDNS01
			return apierrors.IsInvalid(k8sClient.Update(ctx, changed))
		}).Should(BeTrue())
	})
})

var _ = Describe("TLSCertificate reconciler", func() {
	var ns string
	BeforeEach(func() { ns = newProjectNamespace(k8sClient) })

	It("accepts an HTTP01 certificate, mirrors challenges, copies the secret and cleans up", func() {
		tc := newTLSCertificate(ns, "web", certificatesv1alpha1.IssuanceModeAuto, "app.example.com")
		Expect(k8sClient.Create(ctx, tc)).To(Succeed())
		certName := certNameFor(projectA, tc)

		By("accepting the spec and creating the service-side Certificate")
		Eventually(get(tc)).Should(And(
			hasCondition(certificatesv1alpha1.ConditionAccepted, metav1.ConditionTrue, "Accepted"),
			hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionFalse, "Pending"),
			HaveField("Status.Issuance", certificatesv1alpha1.ChallengeTypeHTTP01),
			HaveField("Status.SecretRef.Name", "web-tls"),
			HaveField("Status.RequiredDNSRecords", BeEmpty()),
			HaveField("Finalizers", ContainElement(tlsCertificateFinalizer)),
		))

		var cert cmv1.Certificate
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: serviceNamespace, Name: certName}, &cert)).To(Succeed())
		Expect(cert.Spec.DNSNames).To(Equal([]string{"app.example.com"}))
		Expect(cert.Spec.IssuerRef.Name).To(Equal(http01Issuer))
		Expect(cert.Spec.IssuerRef.Kind).To(Equal(cmv1.ClusterIssuerKind))
		Expect(cert.Spec.SecretTemplate.Labels).To(Equal(map[string]string{UpstreamUIDLabel: string(tc.UID)}))
		Expect(cert.Spec.SecretName).To(Equal(issuingSecretName(certName)))
		Expect(cert.Labels).To(HaveKeyWithValue(downstreamclient.UpstreamOwnerNameLabel, "web"))
		Expect(cert.Labels).To(HaveKeyWithValue(downstreamclient.UpstreamOwnerNamespaceLabel, ns))
		Expect(cert.Labels).To(HaveKeyWithValue(downstreamclient.UpstreamOwnerClusterNameLabel, "cluster-"+projectA))
		Expect(cert.Labels).To(HaveKeyWithValue(UpstreamUIDLabel, string(tc.UID)))

		By("mirroring live ACME challenges")
		order := &acmev1.Order{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   serviceNamespace,
				Name:        certName + "-1",
				Annotations: map[string]string{cmv1.CertificateNameKey: certName},
			},
			Spec: acmev1.OrderSpec{
				Request:   []byte("csr"),
				IssuerRef: cmmeta.ObjectReference{Name: http01Issuer, Kind: cmv1.ClusterIssuerKind},
				DNSNames:  []string{"app.example.com"},
			},
		}
		Expect(k8sClient.Create(ctx, order)).To(Succeed())
		isController := true
		challenge := &acmev1.Challenge{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: serviceNamespace,
				Name:      certName + "-1-0",
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: acmev1.SchemeGroupVersion.String(),
					Kind:       "Order",
					Name:       order.Name,
					UID:        order.UID,
					Controller: &isController,
				}},
			},
			Spec: acmev1.ChallengeSpec{
				URL:              "https://acme.example/chall/1",
				AuthorizationURL: "https://acme.example/authz/1",
				DNSName:          "app.example.com",
				Type:             acmev1.ACMEChallengeTypeHTTP01,
				Token:            "token-1",
				Key:              "token-1.thumbprint",
				Solver:           acmev1.ACMEChallengeSolver{HTTP01: &acmev1.ACMEChallengeSolverHTTP01{}},
				IssuerRef:        cmmeta.ObjectReference{Name: http01Issuer, Kind: cmv1.ClusterIssuerKind},
			},
		}
		Expect(k8sClient.Create(ctx, challenge)).To(Succeed())
		Eventually(get(tc)).Should(HaveField("Status.Challenges", ConsistOf(certificatesv1alpha1.ACMEChallenge{
			DNSName: "app.example.com",
			Type:    certificatesv1alpha1.ChallengeTypeHTTP01,
			Token:   "token-1",
			Key:     "token-1.thumbprint",
			State:   certificatesv1alpha1.ChallengeStatePending,
		})))

		By("reporting an in-flight order with its ACME error")
		cert.Status.Conditions = []cmv1.CertificateCondition{{
			Type:   cmv1.CertificateConditionIssuing,
			Status: cmmeta.ConditionTrue,
			Reason: "Issuing",
		}}
		Expect(k8sClient.Status().Update(ctx, &cert)).To(Succeed())
		challenge.Status.State = acmev1.Invalid
		challenge.Status.Reason = "connection refused"
		Expect(k8sClient.Status().Update(ctx, challenge)).To(Succeed())
		Eventually(get(tc)).Should(And(
			hasCondition(certificatesv1alpha1.ConditionIssuing, metav1.ConditionTrue, "OrderInFlight"),
			WithTransform(func(tc *certificatesv1alpha1.TLSCertificate) string {
				return condition(tc, certificatesv1alpha1.ConditionIssuing).Message
			}, Equal("connection refused")),
			HaveField("Status.Challenges", ConsistOf(HaveField("State", certificatesv1alpha1.ChallengeStateInvalid))),
		))

		By("copying the issued secret into the project")
		crt := issueSecret(certName, tc.UID, "app.example.com")
		Eventually(get(tc)).Should(And(
			hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionTrue, "Issued"),
			HaveField("Status.NotAfter", Not(BeNil())),
			HaveField("Status.ServiceSecretRef", Equal(&certificatesv1alpha1.ServiceSecretReference{Namespace: serviceNamespace, Name: certName})),
		))
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "web-tls"}, &secret)).To(Succeed())
		Expect(secret.Type).To(Equal(corev1.SecretTypeTLS))
		Expect(secret.Data[corev1.TLSCertKey]).To(Equal(crt))
		var stored corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: serviceNamespace, Name: certName}, &stored)).To(Succeed())
		Expect(stored.Data[corev1.TLSCertKey]).To(Equal(crt))
		Expect(stored.OwnerReferences).To(BeEmpty())
		Expect(metav1.IsControlledBy(&secret, get(tc)(Default))).To(BeTrue())

		By("deleting service-side resources on deletion and leaving the project secret to garbage collection")
		Expect(k8sClient.Delete(ctx, tc)).To(Succeed())
		Eventually(func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(tc), &certificatesv1alpha1.TLSCertificate{}))
		}).Should(BeTrue())
		for _, obj := range []client.Object{&cmv1.Certificate{}, &corev1.Secret{}, &corev1.ConfigMap{}} {
			Expect(apierrors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Namespace: serviceNamespace, Name: certName}, obj))).To(BeTrue())
		}
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Namespace: serviceNamespace, Name: issuingSecretName(certName)}, &corev1.Secret{}))).To(BeTrue())
	})

	It("gates DNS01 issuance on a project-bound delegation target and suspends renewal when delegation is lost", func() {
		tc := newTLSCertificate(ns, "wild", certificatesv1alpha1.IssuanceModeAuto, "*.wild.example.com", "wild.example.com")
		Expect(k8sClient.Create(ctx, tc)).To(Succeed())
		certName := certNameFor(projectA, tc)
		targetPattern := regexp.MustCompile(`^[0-9a-f]{32}\.` + regexp.QuoteMeta(delegationZone) + `$`)

		By("publishing a random delegation target and waiting for the CNAME")
		Eventually(get(tc)).Should(And(
			HaveField("Status.Issuance", certificatesv1alpha1.ChallengeTypeDNS01),
			HaveField("Status.DelegationTarget", MatchRegexp(targetPattern.String())),
			hasCondition(certificatesv1alpha1.ConditionDNSDelegationReady, metav1.ConditionFalse, "CNAMENotFound"),
			hasCondition(certificatesv1alpha1.ConditionIssuing, metav1.ConditionFalse, "WaitingForDNSDelegation"),
		))
		target := get(tc)(Default).Status.DelegationTarget
		Expect(get(tc)(Default).Status.RequiredDNSRecords).To(ConsistOf(certificatesv1alpha1.RequiredDNSRecord{
			Name:    "_acme-challenge.wild.example.com",
			Type:    "CNAME",
			Content: target,
			Purpose: certificatesv1alpha1.DNSRecordPurposeCertificate,
		}))
		Consistently(serviceCertificateExists(certName), time.Second).Should(BeFalse())

		By("ignoring a delegation target written into status")
		resolver.set("_acme-challenge.wild.example.com", "attacker."+delegationZone)
		Eventually(func() error {
			tampered := get(tc)(Default)
			tampered.Status.DelegationTarget = "attacker." + delegationZone
			return k8sClient.Status().Update(ctx, tampered)
		}).Should(Succeed())
		Eventually(get(tc)).Should(HaveField("Status.DelegationTarget", target))
		Consistently(serviceCertificateExists(certName), time.Second).Should(BeFalse())

		By("creating the Certificate once the CNAME resolves to the target")
		resolver.set("_acme-challenge.wild.example.com", target)
		Eventually(get(tc)).Should(hasCondition(certificatesv1alpha1.ConditionDNSDelegationReady, metav1.ConditionTrue, "CNAMEResolved"))
		Eventually(serviceCertificateExists(certName)).Should(BeTrue())
		var cert cmv1.Certificate
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: serviceNamespace, Name: certName}, &cert)).To(Succeed())
		Expect(cert.Spec.IssuerRef.Name).To(Equal(dns01Issuer))
		Expect(cert.Spec.DNSNames).To(Equal([]string{"*.wild.example.com", "wild.example.com"}))

		issueSecret(certName, tc.UID, "*.wild.example.com", "wild.example.com")
		Eventually(get(tc)).Should(hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionTrue, "Issued"))

		By("keeping the Certificate through transient lookup failures")
		resolver.fail("_acme-challenge.wild.example.com")
		Eventually(get(tc)).Should(hasCondition(certificatesv1alpha1.ConditionDNSDelegationReady, metav1.ConditionUnknown, "LookupFailed"))
		Consistently(serviceCertificateExists(certName), 3*time.Second).Should(BeTrue())

		By("suspending renewal only after repeated definitive failures, keeping the service's copy")
		resolver.remove("_acme-challenge.wild.example.com")
		Eventually(get(tc)).Should(hasCondition(certificatesv1alpha1.ConditionDNSDelegationReady, metav1.ConditionFalse, "CNAMENotFound"))
		Expect(serviceCertificateExists(certName)()).To(BeTrue(), "one definitive failure must not suspend")
		Eventually(serviceCertificateExists(certName)).Should(BeFalse())

		By("surviving cert-manager or garbage collection removing its own Secret")
		Expect(k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: serviceNamespace, Name: issuingSecretName(certName)}})).To(Succeed())
		Eventually(get(tc)).Should(And(
			hasCondition(certificatesv1alpha1.ConditionIssuing, metav1.ConditionFalse, "WaitingForDNSDelegation"),
			hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionTrue, "Issued"),
			HaveField("Status.ServiceSecretRef", Equal(&certificatesv1alpha1.ServiceSecretReference{Namespace: serviceNamespace, Name: certName})),
		))
		Consistently(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Namespace: serviceNamespace, Name: certName}, &corev1.Secret{})
		}, time.Second).Should(Succeed())
		Consistently(serviceCertificateExists(certName), time.Second).Should(BeFalse())

		By("resuming once the CNAME is restored")
		resolver.set("_acme-challenge.wild.example.com", target)
		Eventually(serviceCertificateExists(certName)).Should(BeTrue())

		By("keeping the delegation target when the TLSCertificate is recreated in the same namespace")
		Expect(k8sClient.Delete(ctx, tc)).To(Succeed())
		Eventually(func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Namespace: serviceNamespace, Name: certName}, &corev1.ConfigMap{}))
		}).Should(BeTrue())
		Eventually(func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(tc), &certificatesv1alpha1.TLSCertificate{}))
		}).Should(BeTrue())

		recreated := newTLSCertificate(ns, "wild", certificatesv1alpha1.IssuanceModeAuto, "*.wild.example.com", "wild.example.com")
		Expect(k8sClient.Create(ctx, recreated)).To(Succeed())
		Eventually(get(recreated)).Should(And(
			HaveField("Status.DelegationTarget", target),
			hasCondition(certificatesv1alpha1.ConditionDNSDelegationReady, metav1.ConditionTrue, "CNAMEResolved"),
		))
		Eventually(serviceCertificateExists(certNameFor(projectA, recreated))).Should(BeTrue())

		By("assigning a different target to the same name in another namespace")
		other := newTLSCertificate(newProjectNamespace(k8sClient), "wild", certificatesv1alpha1.IssuanceModeAuto, "*.wild.example.com")
		Expect(k8sClient.Create(ctx, other)).To(Succeed())
		Eventually(get(other)).Should(HaveField("Status.DelegationTarget", And(MatchRegexp(targetPattern.String()), Not(Equal(target)))))
		Consistently(serviceCertificateExists(certNameFor(projectA, other)), time.Second).Should(BeFalse())
	})

	It("lists a target per name and sets delegationTarget only for a single base name", func() {
		tc := newTLSCertificate(ns, "multi", certificatesv1alpha1.IssuanceModeDNS01, "*.a.example.com", "b.example.com")
		Expect(k8sClient.Create(ctx, tc)).To(Succeed())
		Eventually(get(tc)).Should(HaveField("Status.RequiredDNSRecords", HaveLen(2)))
		got := get(tc)(Default)
		Expect(got.Status.DelegationTarget).To(BeEmpty())
		Expect(got.Status.RequiredDNSRecords[0].Content).NotTo(Equal(got.Status.RequiredDNSRecords[1].Content))
	})

	It("assigns a new target when the namespace is deleted and recreated", func() {
		nsName := newProjectNamespace(k8sClient)
		tc := newTLSCertificate(nsName, "recreate", certificatesv1alpha1.IssuanceModeDNS01, "*.recreate.example.com")
		Expect(k8sClient.Create(ctx, tc)).To(Succeed())
		Eventually(get(tc)).Should(HaveField("Status.DelegationTarget", Not(BeEmpty())))
		before := get(tc)(Default).Status.DelegationTarget

		Expect(k8sClient.Delete(ctx, tc)).To(Succeed())
		Eventually(func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(tc), &certificatesv1alpha1.TLSCertificate{}))
		}).Should(BeTrue())

		clientset, err := kubernetes.NewForConfig(cfg)
		Expect(err).NotTo(HaveOccurred())
		var namespace corev1.Namespace
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: nsName}, &namespace)).To(Succeed())
		oldUID := namespace.UID
		Expect(k8sClient.Delete(ctx, &namespace)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: nsName}, &namespace)).To(Succeed())
		namespace.Spec.Finalizers = nil
		_, err = clientset.CoreV1().Namespaces().Finalize(ctx, &namespace, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKey{Name: nsName}, &corev1.Namespace{}))
		}).Should(BeTrue())

		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName}})).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: nsName}, &namespace)).To(Succeed())
		Expect(namespace.UID).NotTo(Equal(oldUID))

		recreated := newTLSCertificate(nsName, "recreate", certificatesv1alpha1.IssuanceModeDNS01, "*.recreate.example.com")
		Eventually(func() error { return k8sClient.Create(ctx, recreated) }).Should(Succeed())
		Eventually(get(recreated)).Should(HaveField("Status.DelegationTarget", And(Not(BeEmpty()), Not(Equal(before)))))
	})

	It("replaces the stored copy only with a newer, matching issuance and carries renewals to the project", func() {
		tc := newTLSCertificate(ns, "rotate", certificatesv1alpha1.IssuanceModeAuto, "rotate.example.com")
		Expect(k8sClient.Create(ctx, tc)).To(Succeed())
		certName := certNameFor(projectA, tc)
		Eventually(serviceCertificateExists(certName)).Should(BeTrue())

		issuing := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: serviceNamespace,
			Name:      issuingSecretName(certName),
			Labels:    map[string]string{UpstreamUIDLabel: string(tc.UID)},
		}, Type: corev1.SecretTypeTLS}
		write := func(crt, key []byte) {
			Eventually(func() error {
				var current corev1.Secret
				err := k8sClient.Get(ctx, client.ObjectKeyFromObject(issuing), &current)
				if apierrors.IsNotFound(err) {
					fresh := issuing.DeepCopy()
					fresh.Data = map[string][]byte{corev1.TLSCertKey: crt, corev1.TLSPrivateKeyKey: key}
					return k8sClient.Create(ctx, fresh)
				}
				if err != nil {
					return err
				}
				current.Data = map[string][]byte{corev1.TLSCertKey: crt, corev1.TLSPrivateKeyKey: key}
				return k8sClient.Update(ctx, &current)
			}).Should(Succeed())
		}
		projectCopy := func(g Gomega) []byte {
			var secret corev1.Secret
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "rotate-tls"}, &secret)).To(Succeed())
			return secret.Data[corev1.TLSCertKey]
		}
		now := time.Now()

		By("copying the first issuance into the project")
		first, firstKey := selfSignedPEMAt(now.Add(-48*time.Hour), now.Add(60*24*time.Hour), "rotate.example.com")
		write(first, firstKey)
		Eventually(projectCopy).Should(Equal(first))

		By("carrying a renewal to the project copy")
		renewed, renewedKey := selfSignedPEMAt(now.Add(-24*time.Hour), now.Add(90*24*time.Hour), "rotate.example.com")
		write(renewed, renewedKey)
		Eventually(projectCopy).Should(Equal(renewed))

		By("adopting an emergency re-key with a shorter lifetime")
		rekeyed, rekeyedKey := selfSignedPEMAt(now.Add(-time.Hour), now.Add(7*24*time.Hour), "rotate.example.com")
		write(rekeyed, rekeyedKey)
		Eventually(projectCopy).Should(Equal(rekeyed))

		By("refusing an older issuance")
		older, olderKey := selfSignedPEMAt(now.Add(-72*time.Hour), now.Add(120*24*time.Hour), "rotate.example.com")
		write(older, olderKey)
		Consistently(projectCopy, time.Second).Should(Equal(rekeyed))

		By("refusing a certificate whose key does not match")
		mismatched, _ := selfSignedPEMAt(now.Add(-time.Minute), now.Add(90*24*time.Hour), "rotate.example.com")
		_, otherKey := selfSignedPEMAt(now.Add(-time.Minute), now.Add(90*24*time.Hour), "rotate.example.com")
		write(mismatched, otherKey)
		Consistently(projectCopy, time.Second).Should(Equal(rekeyed))

		By("refusing a certificate with an extra name")
		extra, extraKey := selfSignedPEMAt(now.Add(-time.Minute), now.Add(90*24*time.Hour), "rotate.example.com", "extra.attacker.example")
		write(extra, extraKey)
		Consistently(projectCopy, time.Second).Should(Equal(rekeyed))

		var stored corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: serviceNamespace, Name: certName}, &stored)).To(Succeed())
		Expect(stored.Data[corev1.TLSCertKey]).To(Equal(rekeyed))
		Eventually(get(tc)).Should(hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionTrue, "Issued"))
	})

	It("rejects names under a denied domain suffix and suspends any existing Certificate", func() {
		tc := newTLSCertificate(ns, "platform", certificatesv1alpha1.IssuanceModeAuto, "app.datumproxy.net")
		Expect(k8sClient.Create(ctx, tc)).To(Succeed())
		certName := certNameFor(projectA, tc)
		Expect(k8sClient.Create(ctx, &cmv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: serviceNamespace,
				Name:      certName,
				Labels:    map[string]string{UpstreamUIDLabel: string(tc.UID)},
			},
			Spec: cmv1.CertificateSpec{
				SecretName: certName,
				DNSNames:   []string{"app.datumproxy.net"},
				IssuerRef:  cmmeta.ObjectReference{Name: http01Issuer, Kind: cmv1.ClusterIssuerKind},
			},
		})).To(Succeed())

		Eventually(get(tc)).Should(And(
			hasCondition(certificatesv1alpha1.ConditionAccepted, metav1.ConditionFalse, "InvalidSpec"),
			hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionFalse, "NotAccepted"),
		))
		Eventually(serviceCertificateExists(certName)).Should(BeFalse())
	})

	It("never copies an issued secret bound to another TLSCertificate or missing requested names", func() {
		tc := newTLSCertificate(ns, "reuse", certificatesv1alpha1.IssuanceModeAuto, "reuse.example.com")
		Expect(k8sClient.Create(ctx, tc)).To(Succeed())
		certName := certNameFor(projectA, tc)
		Eventually(serviceCertificateExists(certName)).Should(BeTrue())

		By("ignoring a secret labelled for a previous TLSCertificate")
		issueSecret(certName, types.UID("previous-tenant"), "reuse.example.com")
		Consistently(get(tc), time.Second).Should(hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionFalse, "Pending"))
		Expect(apierrors.IsNotFound(projectSecret(k8sClient, ns, "reuse-tls")())).To(BeTrue())

		By("ignoring a certificate that does not cover the requested names")
		Expect(k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: serviceNamespace, Name: issuingSecretName(certName)}})).To(Succeed())
		issueSecret(certName, tc.UID, "other.example.com")
		Consistently(get(tc), time.Second).Should(hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionFalse, "Pending"))
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Namespace: serviceNamespace, Name: certName}, &corev1.Secret{}))).To(BeTrue())
		Expect(apierrors.IsNotFound(projectSecret(k8sClient, ns, "reuse-tls")())).To(BeTrue())
	})

	It("refuses to take over a project Secret it does not own", func() {
		original := map[string][]byte{"password": []byte("hunter2")}
		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "db-credentials"},
			Data:       original,
		})).To(Succeed())

		tc := newTLSCertificate(ns, "takeover", certificatesv1alpha1.IssuanceModeAuto, "takeover.example.com")
		tc.Spec.SecretName = "db-credentials"
		Expect(k8sClient.Create(ctx, tc)).To(Succeed())
		certName := certNameFor(projectA, tc)
		Eventually(serviceCertificateExists(certName)).Should(BeTrue())
		issueSecret(certName, tc.UID, "takeover.example.com")

		Eventually(get(tc)).Should(hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionFalse, "SecretConflict"))
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "db-credentials"}, &secret)).To(Succeed())
		Expect(secret.Data).To(Equal(original))
		Expect(secret.OwnerReferences).To(BeEmpty())

		Expect(k8sClient.Delete(ctx, tc)).To(Succeed())
		Eventually(func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(tc), &certificatesv1alpha1.TLSCertificate{}))
		}).Should(BeTrue())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "db-credentials"}, &secret)).To(Succeed())
	})

	It("keeps the same namespace and name in two projects apart", func() {
		nsB := newProjectNamespace(k8sClientB)
		Expect(k8sClientB.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
		_ = nsB

		tcA := newTLSCertificate(ns, "shared", certificatesv1alpha1.IssuanceModeAuto, "a.example.com")
		tcB := newTLSCertificate(ns, "shared", certificatesv1alpha1.IssuanceModeAuto, "b.example.com")
		Expect(k8sClient.Create(ctx, tcA)).To(Succeed())
		Expect(k8sClientB.Create(ctx, tcB)).To(Succeed())
		nameA, nameB := certNameFor(projectA, tcA), certNameFor(projectB, tcB)
		Expect(nameA).NotTo(Equal(nameB))

		Eventually(serviceCertificateExists(nameA)).Should(BeTrue())
		Eventually(serviceCertificateExists(nameB)).Should(BeTrue())
		var certB cmv1.Certificate
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: serviceNamespace, Name: nameB}, &certB)).To(Succeed())
		Expect(certB.Spec.DNSNames).To(Equal([]string{"b.example.com"}))
		Expect(certB.Labels).To(HaveKeyWithValue(downstreamclient.UpstreamOwnerClusterNameLabel, "cluster-"+projectB))

		crtB := issueSecret(nameB, tcB.UID, "b.example.com")
		Eventually(getFrom(k8sClientB, tcB)).Should(hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionTrue, "Issued"))
		var secret corev1.Secret
		Expect(k8sClientB.Get(ctx, types.NamespacedName{Namespace: ns, Name: "shared-tls"}, &secret)).To(Succeed())
		Expect(secret.Data[corev1.TLSCertKey]).To(Equal(crtB))
		Expect(apierrors.IsNotFound(projectSecret(k8sClient, ns, "shared-tls")())).To(BeTrue())
		Expect(get(tcA)(Default)).To(hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionFalse, "Pending"))
	})
})
