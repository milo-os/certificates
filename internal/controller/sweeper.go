// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"go.miloapis.com/milo/pkg/downstreamclient"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/log"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	"sigs.k8s.io/multicluster-runtime/pkg/multicluster"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"
)

const (
	defaultSweepInterval    = 10 * time.Minute
	defaultSweepGracePeriod = time.Hour
)

// ProjectChecker reports whether a project still exists, independently of
// whether its control plane is currently connected.
type ProjectChecker interface {
	ProjectExists(ctx context.Context, clusterName multicluster.ClusterName) (bool, error)
}

// ProjectCheckerFunc adapts a function to ProjectChecker.
type ProjectCheckerFunc func(ctx context.Context, clusterName multicluster.ClusterName) (bool, error)

func (f ProjectCheckerFunc) ProjectExists(ctx context.Context, clusterName multicluster.ClusterName) (bool, error) {
	return f(ctx, clusterName)
}

// OrphanSweeper removes service-side Certificates, issued Secrets and
// delegation anchors whose TLSCertificate was deleted or whose project was
// deleted. A project that is merely disconnected is never swept. A resource is
// removed only after its owner has been confirmed missing for GracePeriod.
type OrphanSweeper struct {
	Manager              mcmanager.Manager
	Projects             ProjectChecker
	CertificateNamespace string
	CertManager          cluster.Cluster
	Interval             time.Duration
	GracePeriod          time.Duration

	missingSince map[string]time.Time
	now          func() time.Time
}

func (s *OrphanSweeper) NeedLeaderElection() bool { return true }

func (s *OrphanSweeper) Start(ctx context.Context) error {
	interval := s.Interval
	if interval <= 0 {
		interval = defaultSweepInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.Sweep(ctx); err != nil {
				log.FromContext(ctx).Error(err, "orphan sweep failed")
			}
		}
	}
}

// Sweep runs one pass over the service namespace.
func (s *OrphanSweeper) Sweep(ctx context.Context) error {
	if s.missingSince == nil {
		s.missingSince = map[string]time.Time{}
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	grace := s.GracePeriod
	if grace <= 0 {
		grace = defaultSweepGracePeriod
	}

	c := s.Manager.GetLocalManager().GetClient()
	cm := c
	selector := client.HasLabels{UpstreamUIDLabel}
	cmSelector := []client.ListOption{client.InNamespace(s.CertificateNamespace), selector}
	if s.CertManager != nil {
		cm = s.CertManager.GetClient()
		cmSelector = append(cmSelector, client.MatchingLabels{ManagedByLabel: managedBy})
	}

	owners := map[string]map[string]string{}
	seen := map[string]bool{}
	var certs cmv1.CertificateList
	if err := cm.List(ctx, &certs, cmSelector...); err != nil {
		return err
	}
	for i := range certs.Items {
		owners[certs.Items[i].Name] = certs.Items[i].Labels
		seen[certs.Items[i].Name] = true
	}
	var anchors corev1.ConfigMapList
	if err := c.List(ctx, &anchors, client.InNamespace(s.CertificateNamespace), selector); err != nil {
		return err
	}
	for i := range anchors.Items {
		owners[anchors.Items[i].Name] = anchors.Items[i].Labels
		seen[anchors.Items[i].Name] = true
	}
	var secrets corev1.SecretList
	if err := cm.List(ctx, &secrets, cmSelector...); err != nil {
		return err
	}
	for i := range secrets.Items {
		name := strings.TrimSuffix(secrets.Items[i].Name, issuingSecretSuffix)
		seen[name] = true
		if _, ok := owners[name]; !ok {
			owners[name] = nil
		}
	}

	var errs []error
	for certName, labels := range owners {
		orphaned := misnamed(certName, labels)
		if !orphaned {
			var err error
			if orphaned, err = s.ownerMissing(ctx, labels); err != nil {
				log.FromContext(ctx).Error(err, "checking owner", "certificate", certName)
				continue
			}
		}
		if !s.expired(certName, orphaned, now(), grace) {
			continue
		}
		if err := deleteServiceResources(ctx, cm, c, s.CertificateNamespace, certName); err != nil {
			log.FromContext(ctx).Error(err, "removing orphaned certificate", "certificate", certName)
			errs = append(errs, err)
			continue
		}
		if req, ok := upstreamRequest(labels); ok {
			delegationUnconfirmedSeconds.DeleteLabelValues(string(req.ClusterName), req.Namespace, req.Name)
		}
		delete(s.missingSince, certName)
		log.FromContext(ctx).Info("removed orphaned certificate", "certificate", certName)
	}
	var delegationAnchors corev1.ConfigMapList
	if err := c.List(ctx, &delegationAnchors, client.InNamespace(s.CertificateNamespace), client.HasLabels{DelegationAnchorLabel}); err != nil {
		return err
	}
	for i := range delegationAnchors.Items {
		anchor := &delegationAnchors.Items[i]
		seen[anchor.Name] = true
		orphaned, err := s.namespaceMissing(ctx, anchor.Labels)
		if err != nil {
			log.FromContext(ctx).Error(err, "checking delegation anchor", "anchor", anchor.Name)
			continue
		}
		if !s.expired(anchor.Name, orphaned, now(), grace) {
			continue
		}
		if err := client.IgnoreNotFound(c.Delete(ctx, anchor)); err != nil {
			log.FromContext(ctx).Error(err, "removing delegation anchor", "anchor", anchor.Name)
			errs = append(errs, fmt.Errorf("deleting delegation anchor %s/%s: %w", anchor.Namespace, anchor.Name, err))
			continue
		}
		delete(s.missingSince, anchor.Name)
		log.FromContext(ctx).Info("removed delegation anchor of a deleted namespace", "anchor", anchor.Name)
	}

	for certName := range s.missingSince {
		if !seen[certName] {
			delete(s.missingSince, certName)
		}
	}
	return errors.Join(errs...)
}

func misnamed(certName string, labels map[string]string) bool {
	uid := labels[UpstreamUIDLabel]
	return uid != "" && certName != certificatesv1alpha1.StoredSecretName(types.UID(uid))
}

func (s *OrphanSweeper) ownerMissing(ctx context.Context, labels map[string]string) (bool, error) {
	if labels == nil {
		return true, nil
	}
	req, ok := upstreamRequest(labels)
	if !ok {
		return false, nil
	}
	cl, err := s.Manager.GetCluster(ctx, req.ClusterName)
	if err != nil {
		if s.Projects == nil {
			return false, nil
		}
		exists, err := s.Projects.ProjectExists(ctx, req.ClusterName)
		return err == nil && !exists, err
	}
	var tc certificatesv1alpha1.TLSCertificate
	err = cl.GetAPIReader().Get(ctx, req.NamespacedName, &tc)
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return string(tc.UID) != labels[UpstreamUIDLabel], nil
}

// expired tracks how long name has been orphaned and reports whether the grace
// period has passed.
func (s *OrphanSweeper) expired(name string, orphaned bool, now time.Time, grace time.Duration) bool {
	if !orphaned {
		delete(s.missingSince, name)
		return false
	}
	first, seen := s.missingSince[name]
	if !seen {
		s.missingSince[name] = now
		return false
	}
	return now.Sub(first) >= grace
}

// namespaceMissing reports whether the project namespace a delegation anchor
// is bound to was deleted or recreated, or its whole project was deleted.
func (s *OrphanSweeper) namespaceMissing(ctx context.Context, labels map[string]string) (bool, error) {
	clusterName := multicluster.ClusterName(strings.TrimPrefix(
		strings.ReplaceAll(labels[downstreamclient.UpstreamOwnerClusterNameLabel], "_", "/"), "cluster-"))
	cl, err := s.Manager.GetCluster(ctx, clusterName)
	if err != nil {
		if s.Projects == nil {
			return false, nil
		}
		exists, err := s.Projects.ProjectExists(ctx, clusterName)
		return err == nil && !exists, err
	}
	var ns corev1.Namespace
	err = cl.GetAPIReader().Get(ctx, client.ObjectKey{Name: labels[downstreamclient.UpstreamOwnerNamespaceLabel]}, &ns)
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return string(ns.UID) != labels[NamespaceUIDLabel], nil
}
