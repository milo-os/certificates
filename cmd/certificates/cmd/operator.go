// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/spf13/cobra"
	multiclusterproviders "go.miloapis.com/milo/pkg/multicluster-runtime"
	milomulticluster "go.miloapis.com/milo/pkg/multicluster-runtime/milo"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	"sigs.k8s.io/multicluster-runtime/pkg/multicluster"
	mcsingle "sigs.k8s.io/multicluster-runtime/providers/single"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"
	"go.miloapis.com/certificates/internal/config"
	"go.miloapis.com/certificates/internal/controller"
	webhookv1alpha1 "go.miloapis.com/certificates/internal/webhook/v1alpha1"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme, serializer.EnableStrict)
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(config.AddToScheme(scheme))
	utilruntime.Must(config.RegisterDefaults(scheme))
	utilruntime.Must(certificatesv1alpha1.AddToScheme(scheme))
	utilruntime.Must(cmv1.AddToScheme(scheme))
	utilruntime.Must(acmev1.AddToScheme(scheme))
}

type issuanceFlags struct {
	certificateNamespace string
	http01ClusterIssuer  string
	dns01ClusterIssuer   string
	dns01DelegationZone  string
	dnsResolverAddress   string
	deniedDomainSuffixes []string
	writerIdentities     []string
	serviceIdentities    []string
	deleterIdentities    []string
	maxConcurrent        int
	maxUnconfirmed       time.Duration
}

func (f issuanceFlags) denied() []string {
	if f.dns01DelegationZone == "" {
		return f.deniedDomainSuffixes
	}
	return append(slices.Clone(f.deniedDomainSuffixes), f.dns01DelegationZone)
}

func (f issuanceFlags) validate() error {
	if f.certificateNamespace == "" {
		return errors.New("--certificate-namespace is required")
	}
	if (f.dns01ClusterIssuer == "") != (f.dns01DelegationZone == "") {
		return errors.New("--dns01-cluster-issuer and --dns01-delegation-zone must be set together")
	}
	return nil
}

func (f issuanceFlags) validateWebhook(enabled bool) error {
	if enabled && len(f.serviceIdentities) == 0 {
		return errors.New("--service-identities is required when the admission webhook is enabled: only those identities may write TLSCertificate status, so without it the service cannot write status")
	}
	return nil
}

func newOperatorCommand(info BuildInfo) *cobra.Command {
	var (
		enableLeaderElection    bool
		leaderElectionNamespace string
		probeAddr               string
		serverConfigFile        string
		issuance                issuanceFlags
	)

	opts := zap.Options{
		Development: true,
	}

	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Run the certificates operator (controller-runtime manager)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

			setupLog := ctrl.Log.WithName("setup")
			setupLog.Info("starting certificates operator",
				"version", info.Version,
				"gitCommit", info.GitCommit,
				"gitTreeState", info.GitTreeState,
				"buildDate", info.BuildDate,
			)

			if err := issuance.validate(); err != nil {
				return err
			}

			var serverConfig config.TLSCertificateOperator
			var configData []byte
			if len(serverConfigFile) > 0 {
				var err error
				configData, err = os.ReadFile(serverConfigFile)
				if err != nil {
					return fmt.Errorf("reading server config from %q: %w", serverConfigFile, err)
				}
			}

			if err := runtime.DecodeInto(codecs.UniversalDecoder(), configData, &serverConfig); err != nil {
				return fmt.Errorf("decoding server config: %w", err)
			}
			config.SetObjectDefaults_TLSCertificateOperator(&serverConfig)

			setupLog.Info("server config loaded",
				"kubeconfigPath", serverConfig.KubeconfigPath,
				"discoveryMode", serverConfig.Discovery.Mode,
			)

			if err := issuance.validateWebhook(serverConfig.WebhookServer != nil); err != nil {
				return err
			}

			cfg, err := serverConfig.RestConfig()
			if err != nil {
				return fmt.Errorf("loading rest config: %w", err)
			}

			ctx := ctrl.SetupSignalHandler()

			bootstrapClient, err := client.New(cfg, client.Options{Scheme: scheme})
			if err != nil {
				return fmt.Errorf("creating bootstrap client: %w", err)
			}

			metricsServerOptions := serverConfig.MetricsServer.Options(ctx, bootstrapClient)

			var webhookServer webhook.Server
			if serverConfig.WebhookServer != nil {
				webhookServer = webhook.NewServer(
					serverConfig.WebhookServer.Options(ctx, bootstrapClient),
				)
			} else {
				setupLog.Info("webhookServer not configured; admission webhook server disabled")
			}

			deploymentCluster, err := cluster.New(cfg, func(o *cluster.Options) {
				o.Scheme = scheme
			})
			if err != nil {
				return fmt.Errorf("creating local cluster: %w", err)
			}

			runnables, provider, projects, err := initializeClusterDiscovery(serverConfig, deploymentCluster)
			if err != nil {
				return fmt.Errorf("initializing cluster discovery: %w", err)
			}

			serviceNamespace := map[string]cache.Config{issuance.certificateNamespace: {}}
			mgrOpts := ctrl.Options{
				Scheme:                  scheme,
				Metrics:                 metricsServerOptions,
				WebhookServer:           webhookServer,
				HealthProbeBindAddress:  probeAddr,
				LeaderElection:          enableLeaderElection,
				LeaderElectionID:        "certificates.miloapis.com",
				LeaderElectionNamespace: leaderElectionNamespace,
				Cache: cache.Options{
					ByObject: map[client.Object]cache.ByObject{
						&corev1.Secret{}:    {Namespaces: serviceNamespace},
						&cmv1.Certificate{}: {Namespaces: serviceNamespace},
						&acmev1.Order{}:     {Namespaces: serviceNamespace},
						&acmev1.Challenge{}: {Namespaces: serviceNamespace},
						&corev1.ConfigMap{}: {Namespaces: serviceNamespace},
					},
				},
			}

			var mgr mcmanager.Manager
			if p, ok := provider.(*milomulticluster.Provider); ok {
				mgr, err = mcmanager.New(cfg, milomulticluster.WithoutAutoStart(p), mgrOpts)
				if err == nil {
					err = milomulticluster.EngageAlways(mgr, p)
				}
			} else {
				mgr, err = mcmanager.New(cfg, provider, mgrOpts)
			}
			if err != nil {
				return fmt.Errorf("creating multicluster manager: %w", err)
			}

			if err := (&controller.TLSCertificateReconciler{
				CertificateNamespace:    issuance.certificateNamespace,
				HTTP01ClusterIssuer:     issuance.http01ClusterIssuer,
				DNS01ClusterIssuer:      issuance.dns01ClusterIssuer,
				DNS01DelegationZone:     issuance.dns01DelegationZone,
				DeniedDomainSuffixes:    issuance.deniedDomainSuffixes,
				Resolver:                controller.NewResolver(issuance.dnsResolverAddress),
				MaxConcurrentReconciles: issuance.maxConcurrent,
				MaxUnconfirmed:          issuance.maxUnconfirmed,
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("creating TLSCertificate controller: %w", err)
			}

			if err := mgr.GetLocalManager().Add(&controller.OrphanSweeper{
				Manager:              mgr,
				Projects:             projects,
				CertificateNamespace: issuance.certificateNamespace,
			}); err != nil {
				return fmt.Errorf("adding orphan sweeper: %w", err)
			}

			if serverConfig.WebhookServer != nil {
				if err := webhookv1alpha1.SetupWebhookWithManager(mgr.GetLocalManager(), &webhookv1alpha1.Validator{
					DeniedDomainSuffixes: issuance.denied(),
					WriterIdentities:     issuance.writerIdentities,
					ServiceIdentities:    issuance.serviceIdentities,
					DeleterIdentities:    issuance.deleterIdentities,
				}); err != nil {
					return fmt.Errorf("creating TLSCertificate webhook: %w", err)
				}
			}

			if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
				return fmt.Errorf("setting up health check: %w", err)
			}
			if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
				return fmt.Errorf("setting up ready check: %w", err)
			}

			g, ctx := errgroup.WithContext(ctx)
			for _, runnable := range runnables {
				g.Go(func() error {
					return ignoreCanceled(runnable.Start(ctx))
				})
			}

			setupLog.Info("starting multicluster manager")
			g.Go(func() error {
				return ignoreCanceled(mgr.Start(ctx))
			})

			return g.Wait()
		},
	}

	cmd.Flags().StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	cmd.Flags().BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	cmd.Flags().StringVar(&leaderElectionNamespace, "leader-elect-namespace", "", "The namespace to use for leader election.")
	cmd.Flags().StringVar(&serverConfigFile, "server-config", "", "Path to the server config file.")
	cmd.Flags().StringVar(&issuance.certificateNamespace, "certificate-namespace", "certificates-system",
		"Namespace on the local cluster that holds the cert-manager Certificates and issued Secrets backing every TLSCertificate.")
	cmd.Flags().StringVar(&issuance.http01ClusterIssuer, "http01-cluster-issuer", "",
		"cert-manager ClusterIssuer used for HTTP01 issuance. HTTP01 TLSCertificates are not accepted when empty.")
	cmd.Flags().StringVar(&issuance.dns01ClusterIssuer, "dns01-cluster-issuer", "",
		"cert-manager ClusterIssuer used for DNS01 issuance. It must follow CNAMEs into --dns01-delegation-zone. DNS01 TLSCertificates are not accepted when empty.")
	cmd.Flags().StringVar(&issuance.dns01DelegationZone, "dns01-delegation-zone", "",
		"DNS zone the DNS01 issuer writes challenge records into. Each name's _acme-challenge record must be a CNAME to the random target listed in the TLSCertificate's status.requiredDNSRecords, under this zone.")
	cmd.Flags().StringSliceVar(&issuance.deniedDomainSuffixes, "denied-domain-suffixes", []string{"datumproxy.net", "datum.net", "datum-staging.net", "datumdomains.net", "miloapis.com", "datumapis.com"},
		"Domains the service never issues for, including every name beneath them. The DNS01 delegation zone is always denied.")
	cmd.Flags().StringSliceVar(&issuance.writerIdentities, "allowed-writer-identities", []string{"system:control@networking.datumapis.com"},
		"Usernames allowed to create, change or delete TLSCertificates. Empty turns off every identity check except the status one.")
	cmd.Flags().StringSliceVar(&issuance.serviceIdentities, "service-identities", nil,
		"Usernames this service uses in project control planes. Only they may write TLSCertificate status. Required when the admission webhook is enabled.")
	cmd.Flags().StringSliceVar(&issuance.deleterIdentities, "allowed-deleter-identities",
		[]string{"system:control@platform.miloapis.com", "system:serviceaccount:kube-system:namespace-controller", "system:serviceaccount:kube-system:generic-garbage-collector"},
		"Usernames allowed to delete TLSCertificates and make metadata-only changes to them, in addition to the writer and service identities: the identities project control planes use for namespace deletion and garbage collection. Milo's controller manager uses system:control@platform.miloapis.com (preview environments use control@platform.miloapis.com, without the system: prefix, and must override this flag); the kube-system ServiceAccounts cover a stock kube-controller-manager.")
	cmd.Flags().DurationVar(&issuance.maxUnconfirmed, "dns01-max-unconfirmed", 48*time.Hour,
		"How long DNS01 renewal continues while delegation lookups keep failing without a definitive answer. Alert on certificates_dns01_delegation_unconfirmed_seconds well before this.")
	cmd.Flags().IntVar(&issuance.maxConcurrent, "max-concurrent-reconciles", 8, "Number of TLSCertificates reconciled in parallel.")
	cmd.Flags().StringVar(&issuance.dnsResolverAddress, "dns-resolver-address", "",
		"host:port of the DNS server used to check DNS01 delegation. Uses the system resolvers when empty.")

	zapFlags := flag.NewFlagSet("zap", flag.ContinueOnError)
	opts.BindFlags(zapFlags)
	cmd.Flags().AddGoFlagSet(zapFlags)

	return cmd
}

func initializeClusterDiscovery(
	serverConfig config.TLSCertificateOperator,
	deploymentCluster cluster.Cluster,
) (runnables []manager.Runnable, provider multicluster.Provider, projects controller.ProjectChecker, err error) {
	switch serverConfig.Discovery.Mode {
	case multiclusterproviders.ProviderSingle:
		runnables = append(runnables, deploymentCluster)
		provider = mcsingle.New("single", deploymentCluster)

	case multiclusterproviders.ProviderMilo:
		discoveryRestConfig, err := serverConfig.Discovery.DiscoveryRestConfig()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to get discovery rest config: %w", err)
		}

		projectRestConfig, err := serverConfig.Discovery.ProjectRestConfig()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to get project rest config: %w", err)
		}

		discoveryManager, err := manager.New(discoveryRestConfig, manager.Options{
			Client: client.Options{
				Cache: &client.CacheOptions{
					Unstructured: true,
				},
			},
			Metrics: metricsserver.Options{BindAddress: "0"},
		})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to set up discovery manager: %w", err)
		}

		provider, err = milomulticluster.New(discoveryManager, milomulticluster.Options{
			ClusterOptions: []cluster.Option{
				func(o *cluster.Options) {
					o.Scheme = scheme
				},
			},
			InternalServiceDiscovery: serverConfig.Discovery.InternalServiceDiscovery,
			ProjectRestConfig:        projectRestConfig,
		})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to create milo project provider: %w", err)
		}

		runnables = append(runnables, discoveryManager)
		projects = projectChecker(discoveryManager.GetAPIReader(), serverConfig.Discovery.InternalServiceDiscovery)

	default:
		return nil, nil, nil, fmt.Errorf("unsupported cluster discovery mode %s", serverConfig.Discovery.Mode)
	}

	return runnables, provider, projects, nil
}

func projectChecker(reader client.Reader, internalServiceDiscovery bool) controller.ProjectChecker {
	gvk := schema.GroupVersionKind{Group: "resourcemanager.miloapis.com", Version: "v1alpha1", Kind: "Project"}
	if internalServiceDiscovery {
		gvk = schema.GroupVersionKind{Group: "infrastructure.miloapis.com", Version: "v1alpha1", Kind: "ProjectControlPlane"}
	}
	return controller.ProjectCheckerFunc(func(ctx context.Context, clusterName multicluster.ClusterName) (bool, error) {
		var project unstructured.Unstructured
		project.SetGroupVersionKind(gvk)
		err := reader.Get(ctx, client.ObjectKey{Name: string(clusterName)}, &project)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return err == nil, err
	})
}

func ignoreCanceled(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
