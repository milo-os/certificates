// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"
	"go.miloapis.com/certificates/internal/config"
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
}

type issuanceFlags struct {
	deniedDomainSuffixes []string
	writerIdentities     []string
	serviceIdentities    []string
	deleterIdentities    []string
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

			setupLog.Info("server config loaded", "kubeconfigPath", serverConfig.KubeconfigPath)

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

			mgr, err := ctrl.NewManager(cfg, ctrl.Options{
				Scheme:                  scheme,
				Metrics:                 metricsServerOptions,
				WebhookServer:           webhookServer,
				HealthProbeBindAddress:  probeAddr,
				LeaderElection:          enableLeaderElection,
				LeaderElectionID:        "certificates.miloapis.com",
				LeaderElectionNamespace: leaderElectionNamespace,
			})
			if err != nil {
				return fmt.Errorf("creating manager: %w", err)
			}

			if serverConfig.WebhookServer != nil {
				if err := webhookv1alpha1.SetupWebhookWithManager(mgr, &webhookv1alpha1.Validator{
					DeniedDomainSuffixes: issuance.deniedDomainSuffixes,
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

			setupLog.Info("starting manager")
			return mgr.Start(ctx)
		},
	}

	cmd.Flags().StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	cmd.Flags().BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	cmd.Flags().StringVar(&leaderElectionNamespace, "leader-elect-namespace", "", "The namespace to use for leader election.")
	cmd.Flags().StringVar(&serverConfigFile, "server-config", "", "Path to the server config file.")
	cmd.Flags().StringSliceVar(&issuance.deniedDomainSuffixes, "denied-domain-suffixes", []string{"datumproxy.net", "datum.net", "datum-staging.net", "datumdomains.net", "miloapis.com", "datumapis.com"},
		"Domains the service never issues for, including every name beneath them.")
	cmd.Flags().StringSliceVar(&issuance.writerIdentities, "allowed-writer-identities", []string{"system:control@networking.datumapis.com"},
		"Usernames allowed to create, change or delete TLSCertificates. Empty turns off every identity check except the status one.")
	cmd.Flags().StringSliceVar(&issuance.serviceIdentities, "service-identities", nil,
		"Usernames this service uses in project control planes. Only they may write TLSCertificate status. Required when the admission webhook is enabled.")
	cmd.Flags().StringSliceVar(&issuance.deleterIdentities, "allowed-deleter-identities",
		[]string{"system:control@platform.miloapis.com", "system:serviceaccount:kube-system:namespace-controller", "system:serviceaccount:kube-system:generic-garbage-collector"},
		"Usernames allowed to delete TLSCertificates and make metadata-only changes to them, in addition to the writer and service identities: the identities project control planes use for namespace deletion and garbage collection. Milo's controller manager uses system:control@platform.miloapis.com (preview environments use control@platform.miloapis.com, without the system: prefix, and must override this flag); the kube-system ServiceAccounts cover a stock kube-controller-manager.")

	zapFlags := flag.NewFlagSet("zap", flag.ContinueOnError)
	opts.BindFlags(zapFlags)
	cmd.Flags().AddGoFlagSet(zapFlags)

	return cmd
}
