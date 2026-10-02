// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var delegationUnconfirmedSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "certificates_dns01_delegation_unconfirmed_seconds",
	Help: "Seconds since a DNS01 TLSCertificate's delegation last had a definitive check result. Renewal is suspended once it passes the maximum; alert well before that.",
}, []string{"cluster", "namespace", "name"})

func init() {
	metrics.Registry.MustRegister(delegationUnconfirmedSeconds)
}
