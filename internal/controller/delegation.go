// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.miloapis.com/milo/pkg/downstreamclient"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/multicluster-runtime/pkg/multicluster"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"
)

const (
	acmeChallengePrefix = "_acme-challenge."
	delegationTokenKey  = "delegationToken"
	dnsLookupTimeout    = 5 * time.Second

	// DelegationAnchorLabel marks the ConfigMaps that hold delegation tokens.
	DelegationAnchorLabel = "certificates.miloapis.com/delegation-anchor"
	// NamespaceUIDLabel binds a delegation token to one project namespace.
	NamespaceUIDLabel = "certificates.miloapis.com/namespace-uid"

	delegationFailuresAnnotation      = "certificates.miloapis.com/delegation-failures"
	delegationFailingSinceAnnotation  = "certificates.miloapis.com/delegation-failing-since"
	delegationLastConfirmedAnnotation = "certificates.miloapis.com/delegation-last-confirmed"
)

type delegationState int

const (
	delegationOK delegationState = iota
	delegationBroken
	delegationUnknown
)

// CNAMEResolver resolves the canonical name of a host. *net.Resolver
// satisfies it.
type CNAMEResolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// NewResolver returns a resolver that uses the Go DNS client, sending queries
// to address when it is set and to the system resolvers otherwise.
func NewResolver(address string) *net.Resolver {
	r := &net.Resolver{PreferGo: true}
	if address != "" {
		r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		}
	}
	return r
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

func newDelegationToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ensureAnchor keeps the per-TLSCertificate anchor ConfigMap, which ties the
// service-side resources for tc back to its project and records how long DNS01
// delegation has been failing.
func (r *TLSCertificateReconciler) ensureAnchor(
	ctx context.Context,
	clusterName multicluster.ClusterName,
	tc *certificatesv1alpha1.TLSCertificate,
	certName string,
) (*corev1.ConfigMap, error) {
	c := r.mgr.GetLocalManager().GetClient()
	anchor := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: certName, Namespace: r.CertificateNamespace}}
	err := c.Get(ctx, client.ObjectKeyFromObject(anchor), anchor)
	switch {
	case apierrors.IsNotFound(err):
		anchor.Labels = serviceLabels(clusterName, tc)
		if err := c.Create(ctx, anchor); err != nil {
			return nil, fmt.Errorf("creating anchor %s: %w", certName, err)
		}
	case err != nil:
		return nil, fmt.Errorf("getting anchor %s: %w", certName, err)
	case anchor.Labels[UpstreamUIDLabel] != string(tc.UID):
		return nil, fmt.Errorf("anchor %s belongs to another TLSCertificate", certName)
	}
	return anchor, nil
}

// delegationTargets returns the delegation target for each base name in tc.
// Each target's random token is stored on the service cluster, keyed by the
// project, the UID of the TLSCertificate's namespace and the base name. A
// TLSCertificate recreated in the same namespace for the same name gets the
// same target, so the CNAME its owner published keeps working, while no other
// project or recreated project can obtain it, and nothing is derived from the
// hostname or read from status.
func (r *TLSCertificateReconciler) delegationTargets(
	ctx context.Context,
	cl cluster.Cluster,
	clusterName multicluster.ClusterName,
	tc *certificatesv1alpha1.TLSCertificate,
) (map[string]string, error) {
	var ns corev1.Namespace
	if err := cl.GetClient().Get(ctx, client.ObjectKey{Name: tc.Namespace}, &ns); err != nil {
		return nil, fmt.Errorf("getting namespace %s: %w", tc.Namespace, err)
	}

	c := r.mgr.GetLocalManager().GetClient()
	targets := map[string]string{}
	for _, base := range baseNames(tc.Spec.DNSNames) {
		name := delegationAnchorName(clusterName, ns.UID, base)
		anchor := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.CertificateNamespace}}
		err := c.Get(ctx, client.ObjectKeyFromObject(anchor), anchor)
		switch {
		case apierrors.IsNotFound(err):
			token, err := newDelegationToken()
			if err != nil {
				return nil, fmt.Errorf("generating delegation token: %w", err)
			}
			anchor.Labels = map[string]string{
				DelegationAnchorLabel:                          "true",
				downstreamclient.UpstreamOwnerClusterNameLabel: clusterLabel(clusterName),
				downstreamclient.UpstreamOwnerNamespaceLabel:   tc.Namespace,
				NamespaceUIDLabel:                              string(ns.UID),
			}
			anchor.Data = map[string]string{delegationTokenKey: token}
			if err := c.Create(ctx, anchor); err != nil {
				return nil, fmt.Errorf("creating delegation anchor %s: %w", name, err)
			}
		case err != nil:
			return nil, fmt.Errorf("getting delegation anchor %s: %w", name, err)
		case anchor.Labels[NamespaceUIDLabel] != string(ns.UID) || anchor.Data[delegationTokenKey] == "":
			return nil, fmt.Errorf("delegation anchor %s does not belong to namespace %s", name, tc.Namespace)
		}
		targets[base] = anchor.Data[delegationTokenKey] + "." + normalizeDNSName(r.DNS01DelegationZone)
	}
	return targets, nil
}

func delegationAnchorName(clusterName multicluster.ClusterName, namespaceUID types.UID, base string) string {
	sum := sha256.Sum256([]byte(string(clusterName) + "/" + string(namespaceUID) + "/" + base))
	return "dt-" + hex.EncodeToString(sum[:16])
}

func baseNames(names []certificatesv1alpha1.DNSName) []string {
	var bases []string
	for _, n := range names {
		base := strings.TrimPrefix(string(n), "*.")
		if !slices.Contains(bases, base) {
			bases = append(bases, base)
		}
	}
	return bases
}

func (r *TLSCertificateReconciler) deniedSuffixes() []string {
	if r.DNS01DelegationZone == "" {
		return r.DeniedDomainSuffixes
	}
	return append(slices.Clone(r.DeniedDomainSuffixes), r.DNS01DelegationZone)
}

func requiredDNS01Records(names []certificatesv1alpha1.DNSName, targets map[string]string) []certificatesv1alpha1.RequiredDNSRecord {
	var records []certificatesv1alpha1.RequiredDNSRecord
	for _, base := range baseNames(names) {
		records = append(records, certificatesv1alpha1.RequiredDNSRecord{
			Name:    acmeChallengePrefix + base,
			Type:    "CNAME",
			Content: targets[base],
			Purpose: certificatesv1alpha1.DNSRecordPurposeCertificate,
		})
	}
	return records
}

// checkDelegation resolves every record. A missing name or a CNAME to the wrong
// target is definitive; any other lookup error leaves the outcome unknown.
func checkDelegation(ctx context.Context, resolver CNAMEResolver, records []certificatesv1alpha1.RequiredDNSRecord) (delegationState, []string) {
	state := delegationOK
	var problems []string
	for _, rec := range records {
		lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
		cname, err := resolver.LookupCNAME(lookupCtx, rec.Name+".")
		cancel()
		var dnsErr *net.DNSError
		switch {
		case err != nil && errors.As(err, &dnsErr) && dnsErr.IsNotFound:
			state = delegationBroken
			problems = append(problems, fmt.Sprintf("%s does not exist", rec.Name))
		case err != nil:
			if state == delegationOK {
				state = delegationUnknown
			}
			problems = append(problems, fmt.Sprintf("%s could not be resolved: %v", rec.Name, err))
		case normalizeDNSName(cname) != rec.Content:
			state = delegationBroken
			problems = append(problems, fmt.Sprintf("%s resolves to %q, want %q", rec.Name, normalizeDNSName(cname), rec.Content))
		}
	}
	return state, problems
}

type delegationRecord struct {
	failures      int
	failingSince  time.Time
	lastConfirmed time.Time
}

type delegationPolicy struct {
	suspendAfterFailures int
	suspendAfter         time.Duration
	maxUnconfirmed       time.Duration
}

func readDelegationRecord(anchor *corev1.ConfigMap) delegationRecord {
	var rec delegationRecord
	rec.failures, _ = strconv.Atoi(anchor.Annotations[delegationFailuresAnnotation])
	rec.failingSince, _ = time.Parse(time.RFC3339, anchor.Annotations[delegationFailingSinceAnnotation])
	rec.lastConfirmed, _ = time.Parse(time.RFC3339, anchor.Annotations[delegationLastConfirmedAnnotation])
	if rec.lastConfirmed.IsZero() {
		rec.lastConfirmed = anchor.CreationTimestamp.Time
	}
	return rec
}

func (rec delegationRecord) write(anchor *corev1.ConfigMap) {
	if anchor.Annotations == nil {
		anchor.Annotations = map[string]string{}
	}
	if rec.failures == 0 {
		delete(anchor.Annotations, delegationFailuresAnnotation)
		delete(anchor.Annotations, delegationFailingSinceAnnotation)
	} else {
		anchor.Annotations[delegationFailuresAnnotation] = strconv.Itoa(rec.failures)
		anchor.Annotations[delegationFailingSinceAnnotation] = rec.failingSince.UTC().Format(time.RFC3339)
	}
	if !rec.lastConfirmed.IsZero() {
		anchor.Annotations[delegationLastConfirmedAnnotation] = rec.lastConfirmed.UTC().Format(time.RFC3339)
	}
}

// next applies the outcome of one check. A definitive result confirms the
// delegation state; a good one clears the failures and a broken one counts
// them. An unknown result changes nothing.
func (rec delegationRecord) next(state delegationState, now time.Time) delegationRecord {
	switch state {
	case delegationOK:
		return delegationRecord{lastConfirmed: now}
	case delegationBroken:
		if rec.failures == 0 || rec.failingSince.IsZero() {
			rec.failingSince = now
		}
		rec.failures++
		rec.lastConfirmed = now
	}
	return rec
}

// suspend reports whether an existing Certificate must stop renewing: after
// enough definitive failures spanning the suspension window, or when no
// definitive result has been seen for maxUnconfirmed.
func (rec delegationRecord) suspend(state delegationState, now time.Time, policy delegationPolicy) bool {
	switch state {
	case delegationBroken:
		return rec.failures >= policy.suspendAfterFailures && now.Sub(rec.failingSince) >= policy.suspendAfter
	case delegationUnknown:
		return now.Sub(rec.lastConfirmed) >= policy.maxUnconfirmed
	}
	return false
}

// recordDelegation stores the outcome of a check on the anchor and reports
// whether an existing Certificate must now be suspended, and how long the
// delegation has gone without a definitive result.
func (r *TLSCertificateReconciler) recordDelegation(ctx context.Context, anchor *corev1.ConfigMap, state delegationState) (bool, time.Duration, error) {
	now := time.Now()
	prev := readDelegationRecord(anchor)
	rec := prev.next(state, now)

	changed := rec.failures != prev.failures ||
		!rec.failingSince.Equal(prev.failingSince) ||
		rec.lastConfirmed.Sub(prev.lastConfirmed) >= time.Minute ||
		anchor.Annotations[delegationLastConfirmedAnnotation] == ""
	if changed {
		rec.write(anchor)
		if err := r.mgr.GetLocalManager().GetClient().Update(ctx, anchor); err != nil {
			return false, 0, fmt.Errorf("recording delegation state on %s: %w", anchor.Name, err)
		}
	}
	return rec.suspend(state, now, r.delegationPolicy()), now.Sub(rec.lastConfirmed), nil
}

func (r *TLSCertificateReconciler) delegationPolicy() delegationPolicy {
	return delegationPolicy{
		suspendAfterFailures: r.suspendAfterFailures(),
		suspendAfter:         r.suspendAfter(),
		maxUnconfirmed:       r.maxUnconfirmed(),
	}
}

func (r *TLSCertificateReconciler) maxUnconfirmed() time.Duration {
	if r.MaxUnconfirmed > 0 {
		return r.MaxUnconfirmed
	}
	return defaultMaxUnconfirmed
}

func (r *TLSCertificateReconciler) suspendAfterFailures() int {
	if r.SuspendAfterFailures > 0 {
		return r.SuspendAfterFailures
	}
	return defaultSuspendAfterFailures
}

func (r *TLSCertificateReconciler) suspendAfter() time.Duration {
	if r.SuspendAfter > 0 {
		return r.SuspendAfter
	}
	return defaultSuspendAfter
}
