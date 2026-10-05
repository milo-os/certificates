// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"time"

	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"go.miloapis.com/milo/pkg/downstreamclient"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func onCertManager(obj client.Object, name string) func() bool {
	return func() bool {
		return certManagerCl.Get(ctx, types.NamespacedName{Namespace: serviceNamespace, Name: name}, obj) == nil
	}
}

func onLocalC(obj client.Object, name string) func() bool {
	return func() bool {
		return k8sClientC.Get(ctx, types.NamespacedName{Namespace: serviceNamespace, Name: name}, obj) == nil
	}
}

func issueOnCertManager(certName string, uid types.UID, names ...string) []byte {
	crt, key := selfSignedPEM(time.Now().Add(90*24*time.Hour), names...)
	Expect(certManagerCl.Create(ctx, &corev1.Secret{
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

var _ = Describe("TLSCertificate reconciler with a separate cert-manager cluster", func() {
	var ns string
	BeforeEach(func() { ns = newProjectNamespace(k8sClientC) })

	getC := func(tc *certificatesv1alpha1.TLSCertificate) func(Gomega) *certificatesv1alpha1.TLSCertificate {
		return getFrom(k8sClientC, tc)
	}

	It("keeps the Certificate, ACME objects and key material on the cert-manager cluster", func() {
		tc := newTLSCertificate(ns, "web", certificatesv1alpha1.IssuanceModeAuto, "web.cm.example.com")
		Expect(k8sClientC.Create(ctx, tc)).To(Succeed())
		certName := certNameFor(tc)

		By("creating the Certificate on the cert-manager cluster only")
		Eventually(getC(tc)).Should(And(
			hasCondition(certificatesv1alpha1.ConditionAccepted, metav1.ConditionTrue, "Accepted"),
			HaveField("Finalizers", ContainElement(tlsCertificateFinalizer)),
		))
		var cert cmv1.Certificate
		Eventually(onCertManager(&cert, certName)).Should(BeTrue())
		Expect(cert.Spec.IssuerRef.Name).To(Equal(http01Issuer))
		Expect(cert.Labels).To(HaveKeyWithValue(downstreamclient.UpstreamOwnerClusterNameLabel, "cluster-"+projectC))
		Expect(cert.Labels).To(HaveKeyWithValue(UpstreamUIDLabel, string(tc.UID)))
		_, err := k8sClientC.RESTMapper().RESTMapping(cmv1.SchemeGroupVersion.WithKind("Certificate").GroupKind())
		Expect(meta.IsNoMatchError(err)).To(BeTrue(), "the local cluster must not need cert-manager CRDs, got %v", err)

		By("mirroring challenges watched on the cert-manager cluster")
		order := &acmev1.Order{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   serviceNamespace,
				Name:        certName + "-1",
				Annotations: map[string]string{cmv1.CertificateNameKey: certName},
			},
			Spec: acmev1.OrderSpec{
				Request:   []byte("csr"),
				IssuerRef: cmmeta.ObjectReference{Name: http01Issuer, Kind: cmv1.ClusterIssuerKind},
				DNSNames:  []string{"web.cm.example.com"},
			},
		}
		Expect(certManagerCl.Create(ctx, order)).To(Succeed())
		isController := true
		Expect(certManagerCl.Create(ctx, &acmev1.Challenge{
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
				URL:              "https://acme.example/chall/cm",
				AuthorizationURL: "https://acme.example/authz/cm",
				DNSName:          "web.cm.example.com",
				Type:             acmev1.ACMEChallengeTypeHTTP01,
				Token:            "token-cm",
				Key:              "token-cm.thumbprint",
				Solver:           acmev1.ACMEChallengeSolver{HTTP01: &acmev1.ACMEChallengeSolverHTTP01{}},
				IssuerRef:        cmmeta.ObjectReference{Name: http01Issuer, Kind: cmv1.ClusterIssuerKind},
			},
		})).To(Succeed())
		Eventually(getC(tc)).Should(HaveField("Status.Challenges", ConsistOf(HaveField("Token", "token-cm"))))

		By("storing the issued key pair on the cert-manager cluster")
		crt := issueOnCertManager(certName, tc.UID, "web.cm.example.com")
		Eventually(getC(tc)).Should(hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionTrue, "Issued"))
		var stored corev1.Secret
		Expect(onCertManager(&stored, certName)()).To(BeTrue())
		Expect(stored.Data[corev1.TLSCertKey]).To(Equal(crt))
		Expect(onLocalC(&corev1.Secret{}, certName)()).To(BeFalse())
		Expect(projectSecrets(k8sClientC, ns)(Default)).To(BeEmpty())

		By("removing the cert-manager cluster resources on deletion")
		Expect(k8sClientC.Delete(ctx, tc)).To(Succeed())
		Eventually(func() bool {
			return apierrors.IsNotFound(k8sClientC.Get(ctx, client.ObjectKeyFromObject(tc), &certificatesv1alpha1.TLSCertificate{}))
		}).Should(BeTrue())
		Expect(onCertManager(&cmv1.Certificate{}, certName)()).To(BeFalse())
		Expect(onCertManager(&corev1.Secret{}, certName)()).To(BeFalse())
		Expect(onCertManager(&corev1.Secret{}, issuingSecretName(certName))()).To(BeFalse())
	})

	It("keeps delegation anchors local and maps cert-manager cluster events back through them", func() {
		tc := newTLSCertificate(ns, "wild", certificatesv1alpha1.IssuanceModeAuto, "*.wild.cm.example.com", "wild.cm.example.com")
		Expect(k8sClientC.Create(ctx, tc)).To(Succeed())
		certName := certNameFor(tc)

		Eventually(getC(tc)).Should(HaveField("Status.DelegationTarget", Not(BeEmpty())))
		target := getC(tc)(Default).Status.DelegationTarget
		Expect(onLocalC(&corev1.ConfigMap{}, certName)()).To(BeTrue())
		Expect(onCertManager(&corev1.ConfigMap{}, certName)()).To(BeFalse())

		resolver.set("_acme-challenge.wild.cm.example.com", target)
		Eventually(onCertManager(&cmv1.Certificate{}, certName)).Should(BeTrue())
		issueOnCertManager(certName, tc.UID, "*.wild.cm.example.com", "wild.cm.example.com")
		Eventually(getC(tc)).Should(hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionTrue, "Issued"))

		By("suspending renewal on the cert-manager cluster when delegation is lost")
		resolver.remove("_acme-challenge.wild.cm.example.com")
		Eventually(onCertManager(&cmv1.Certificate{}, certName)).Should(BeFalse())

		By("reconciling a cert-manager cluster Secret event through the local anchor")
		Expect(certManagerCl.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: serviceNamespace, Name: issuingSecretName(certName)}})).To(Succeed())
		Eventually(getC(tc)).Should(And(
			hasCondition(certificatesv1alpha1.ConditionIssuing, metav1.ConditionFalse, "WaitingForDNSDelegation"),
			hasCondition(certificatesv1alpha1.ConditionReady, metav1.ConditionTrue, "Issued"),
		))
		Expect(onCertManager(&corev1.Secret{}, certName)()).To(BeTrue())

		Expect(k8sClientC.Delete(ctx, tc)).To(Succeed())
		Eventually(onLocalC(&corev1.ConfigMap{}, certName)).Should(BeFalse())
		Expect(onCertManager(&corev1.Secret{}, certName)()).To(BeFalse())
	})

	It("sweeps only its own orphans on the cert-manager cluster and anchors on the local cluster", func() {
		uid := "uid-cm-orphan"
		name := certificatesv1alpha1.StoredSecretName(types.UID(uid))
		foreignUID := "uid-cm-foreign"
		foreign := certificatesv1alpha1.StoredSecretName(types.UID(foreignUID))
		labels := map[string]string{
			ManagedByLabel: managedBy,
			downstreamclient.UpstreamOwnerClusterNameLabel: "cluster-" + projectC,
			downstreamclient.UpstreamOwnerGroupLabel:       certificatesv1alpha1.GroupVersion.Group,
			downstreamclient.UpstreamOwnerKindLabel:        "TLSCertificate",
			downstreamclient.UpstreamOwnerNameLabel:        "gone",
			downstreamclient.UpstreamOwnerNamespaceLabel:   "nowhere",
			UpstreamUIDLabel: uid,
		}
		cert := &cmv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Namespace: serviceNamespace, Name: name, Labels: labels},
			Spec: cmv1.CertificateSpec{
				SecretName: issuingSecretName(name),
				DNSNames:   []string{"orphan.cm.example.com"},
				IssuerRef:  cmmeta.ObjectReference{Name: http01Issuer, Kind: cmv1.ClusterIssuerKind},
			},
		}
		Expect(certManagerCl.Create(ctx, cert)).To(Succeed())
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: serviceNamespace, Name: name, Labels: map[string]string{UpstreamUIDLabel: uid, ManagedByLabel: managedBy}}}
		Expect(certManagerCl.Create(ctx, secret)).To(Succeed())

		foreignLabels := map[string]string{}
		for k, v := range labels {
			foreignLabels[k] = v
		}
		delete(foreignLabels, ManagedByLabel)
		foreignLabels[UpstreamUIDLabel] = foreignUID
		foreignCert := cert.DeepCopy()
		foreignCert.ObjectMeta = metav1.ObjectMeta{Namespace: serviceNamespace, Name: foreign, Labels: foreignLabels}
		Expect(certManagerCl.Create(ctx, foreignCert)).To(Succeed())
		foreignSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: serviceNamespace, Name: foreign + "-other", Labels: map[string]string{UpstreamUIDLabel: foreignUID}}}
		Expect(certManagerCl.Create(ctx, foreignSecret)).To(Succeed())
		anchor := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: serviceNamespace, Name: name, Labels: labels}}
		Expect(k8sClientC.Create(ctx, anchor)).To(Succeed())
		Eventually(onCertManager(&cmv1.Certificate{}, name)).Should(BeTrue())
		Eventually(func(g Gomega) {
			g.Expect(certManagerSetup.GetClient().Get(ctx, client.ObjectKeyFromObject(cert), &cmv1.Certificate{})).To(Succeed())
			g.Expect(certManagerSetup.GetClient().Get(ctx, client.ObjectKeyFromObject(secret), &corev1.Secret{})).To(Succeed())
			g.Expect(certManagerSetup.GetClient().Get(ctx, client.ObjectKeyFromObject(foreignCert), &cmv1.Certificate{})).To(Succeed())
			g.Expect(certManagerSetup.GetClient().Get(ctx, client.ObjectKeyFromObject(foreignSecret), &corev1.Secret{})).To(Succeed())
			g.Expect(certManagerMgr.GetLocalManager().GetClient().Get(ctx, client.ObjectKeyFromObject(anchor), &corev1.ConfigMap{})).To(Succeed())
		}).Should(Succeed())

		now := time.Now()
		sweeper := &OrphanSweeper{
			Manager:              certManagerMgr,
			CertificateNamespace: serviceNamespace,
			CertManager:          certManagerSetup,
			GracePeriod:          time.Hour,
			now:                  func() time.Time { return now },
		}
		Expect(sweeper.Sweep(ctx)).To(Succeed())
		now = now.Add(2 * time.Hour)
		Expect(sweeper.Sweep(ctx)).To(Succeed())

		Expect(onCertManager(&cmv1.Certificate{}, name)()).To(BeFalse())
		Expect(onCertManager(&corev1.Secret{}, name)()).To(BeFalse())
		Expect(onLocalC(&corev1.ConfigMap{}, name)()).To(BeFalse())
		Expect(onCertManager(&cmv1.Certificate{}, foreign)()).To(BeTrue(), "objects without the operator identity must survive the sweep")
		Expect(onCertManager(&corev1.Secret{}, foreign+"-other")()).To(BeTrue(), "objects without the operator identity must survive the sweep")
	})
})
