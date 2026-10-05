# certificates

Certificates, built in. The certificate service issues publicly trusted TLS
certificates for hostnames in Milo project control planes. The issued key pair
stays on the service cluster; projects never receive it.

A project asks for a certificate with a `TLSCertificate`:

```yaml
apiVersion: certificates.miloapis.com/v1alpha1
kind: TLSCertificate
metadata:
  name: web
spec:
  dnsNames:
    - "*.example.com"
    - example.com
  issuance: Auto
```

- `issuance: Auto` uses DNS01 when any name is a wildcard and HTTP01 otherwise.
  HTTP01 cannot issue wildcards.
- The service does not verify that the project controls the names. Callers
  create a `TLSCertificate` only for names they have already verified. Names
  under `--denied-domain-suffixes` and the DNS01 delegation zone are always
  rejected, as are public suffixes and names whose top-level domain is not a
  public ICANN domain.
- HTTP01: the consumer serves each entry in `status.challenges` at
  `http://<dnsName>/.well-known/acme-challenge/<token>` with body `<key>`.
- DNS01: the service assigns each name a random delegation target, listed in
  `status.requiredDNSRecords`, which is authoritative. `status.delegationTarget`
  is set only when the spec has a single DNS01 name.
  The name's owner publishes `_acme-challenge.<name>` as a CNAME to it.
  Targets are held per project namespace and name, so recreating a
  TLSCertificate for the same name in the same namespace keeps the target
  and the published CNAME keeps working. Issuance starts only once every
  CNAME resolves to its exact target.
- Renewal is suspended when delegation is definitively broken (the record
  does not exist, or points elsewhere) on three checks spanning at least 30
  minutes, and a good result resets the count. Timeouts, server failures and
  other lookup errors leave the state alone, but only for
  `--dns01-max-unconfirmed` (48 hours): with no definitive result for that
  long, renewal is suspended and `DNSDelegationReady` turns `Unknown` with
  reason `DelegationUnconfirmed`. The
  `certificates_dns01_delegation_unconfirmed_seconds` metric reports how long
  each certificate has gone unconfirmed; alert on it passing an hour. The
  current certificate keeps being served while suspended.
- `dnsNames` and `issuance` are immutable.
- The key pair is never written to the project control plane, so no project
  user can read the private key, and the API does not name where it is held.
  Once issued, `Ready` turns `True` and `status.notBefore` and
  `status.notAfter` are set.
- Conditions: `Accepted`, `DNSDelegationReady` (DNS01 only), `Issuing` and
  `Ready`.

## How it runs

The service runs on the cluster that hosts cert-manager. It discovers project
control planes through Milo's multicluster-runtime provider and watches
`TLSCertificates` in each one. Per `TLSCertificate` it owns:

- a delegation anchor ConfigMap per project namespace and DNS01 name,
  `dt-<sha256(cluster/namespace-uid/name)[:32]>`, holding the random token.
  It outlives the TLSCertificate and is swept once the namespace or project is
  deleted;
- an anchor ConfigMap recording delegation checks, a cert-manager
  `Certificate`, and the service's own copy of the issued key pair, all named
  `tc-<sha256(uid)[:32]>` in `--certificate-namespace` and labelled with the
  TLSCertificate's UID. cert-manager writes to `<name>-issuing`; the service
  copies each valid issuance into `<name>`, which nothing else owns. The
  Certificate and anchor also carry the upstream cluster, namespace and name;
  the Secrets do not, so edge propagation policies never select them.

In the project control plane it writes only the `TLSCertificate`'s status and
finalizer.

An issuance is copied only when its UID label matches the `TLSCertificate`,
its names equal `spec.dnsNames` exactly, its key matches its certificate, and
it was issued after the copy already held. Ordering by issue time lets an
emergency re-key with a shorter lifetime replace a compromised key at once.

The service deletes the cert-manager `Certificate` whenever the spec is no
longer accepted or DNS01 renewal is suspended, so cert-manager cannot renew
it. The service's copy of the key pair is unaffected, so cert-manager may run
with or without `--enable-certificate-owner-ref`.

A finalizer removes the service-side resources when the `TLSCertificate` is
deleted. A periodic sweep removes them once the `TLSCertificate` or its
project has been confirmed gone for an hour. It also removes, after the same
hour, any service-side resource whose name is not derived from the UID it is
labelled with. A project that is only
disconnected is never swept.

## Platform consumer contract

This is an internal contract for platform components that serve the
certificate, such as the network services operator, not part of the
user-facing API. A component holding read access to Secrets in
`--certificate-namespace` on the cert-manager cluster (`certManagerKubeconfigPath`,
or the service cluster when unset) finds the key pair at:

- namespace: `--certificate-namespace` (`certificates-system` by default);
- name: `StoredSecretName(uid)` from `go.miloapis.com/certificates/api/v1alpha1`,
  which is `tc-` followed by the first 32 hex characters of the SHA-256 of the
  `TLSCertificate`'s UID.

The Secret is `kubernetes.io/tls` and carries the label
`certificates.miloapis.com/upstream-uid: <uid>`; check it before use. Wait for
`Ready=True`, and treat a change in `status.notAfter` as the signal that a
renewal has replaced the key pair.

## Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--certificate-namespace` | `certificates-system` | Namespace holding the service-side Certificates and issued Secrets on the cert-manager cluster, and delegation tokens on the local cluster |
| `--http01-cluster-issuer` | empty | cert-manager ClusterIssuer for HTTP01. HTTP01 requests are not accepted when empty |
| `--dns01-cluster-issuer` | empty | cert-manager ClusterIssuer for DNS01. It must follow CNAMEs (`cnameStrategy: Follow`) and be able to write only to the delegation zone |
| `--dns01-delegation-zone` | empty | Zone the DNS01 issuer writes challenge records into. Required with `--dns01-cluster-issuer` |
| `--denied-domain-suffixes` | `datumproxy.net,datum.net,datum-staging.net,datumdomains.net,miloapis.com,datumapis.com` | Domains never issued for, including every name beneath them |
| `--allowed-writer-identities` | `system:control@networking.datumapis.com` | Usernames allowed to create, change or delete a `TLSCertificate`. Empty turns off every identity check except the status one |
| `--service-identities` | empty | The service's usernames in project control planes. Only they may write status. Required when the webhook is enabled |
| `--allowed-deleter-identities` | `system:control@platform.miloapis.com`, kube-system namespace-controller and generic-garbage-collector | Extra usernames allowed to delete a `TLSCertificate` and make metadata-only changes, such as removing finalizers: whatever deletes namespaces and collects garbage in project control planes. Milo's controller manager uses `system:control@platform.miloapis.com`. Preview environments use `control@platform.miloapis.com`, without the `system:` prefix, and must override this flag. The kube-system ServiceAccounts apply only to a stock kube-controller-manager |
| `--max-concurrent-reconciles` | `8` | TLSCertificates reconciled in parallel |
| `--dns01-max-unconfirmed` | `48h` | How long DNS01 renewal continues while delegation lookups fail without a definitive answer |
| `--dns-resolver-address` | empty | `host:port` of the DNS server used for delegation checks. Uses the system resolvers when empty |
| `--server-config` | empty | Path to the operator config file |
| `--leader-elect`, `--leader-elect-namespace`, `--health-probe-bind-address` | | Standard manager flags |

Point the issuers at the ACME staging endpoint in non-production environments;
the service never hardcodes an ACME server.

## Operator config

```yaml
apiVersion: apiserver.config.miloapis.com/v1alpha1
kind: TLSCertificateOperator
metricsServer:
  bindAddress: "0"
webhookServer: {}
kubeconfigPath: ""
certManagerKubeconfigPath: ""
discovery:
  mode: milo
  internalServiceDiscovery: false
  discoveryKubeconfigPath: /etc/milo/discovery/kubeconfig
  projectKubeconfigPath: /etc/milo/project/kubeconfig
```

- `kubeconfigPath`: the local cluster, which holds leader election, the
  webhook and delegation anchors. Empty uses in-cluster config.
- `certManagerKubeconfigPath`: the cluster that runs cert-manager and holds the
  Certificates, Orders, Challenges and issued Secrets in
  `--certificate-namespace`. Empty uses the local cluster. The namespace must
  already exist there; the operator refuses to start otherwise.
- `discovery.mode`: `single` reconciles `TLSCertificates` in the local cluster,
  `milo` reconciles every project control plane.

## Permissions

On the service cluster, a Role in the certificate namespace covers
`certificates`, `orders` and `challenges` (read), `secrets` and `configmaps`.
The ClusterRole covers only `tlscertificates`.

When `certManagerKubeconfigPath` is set, the local cluster needs only
`configmaps` in the certificate namespace, and the identity in that kubeconfig
needs, on the cert-manager cluster:

- `certificates.cert-manager.io`: get, list, watch, create, update, patch,
  delete in the certificate namespace
- `orders` and `challenges.acme.cert-manager.io`: get, list, watch in the
  certificate namespace
- `secrets`: get, list, watch, create, update, patch, delete in the certificate
  namespace
- `namespaces`: get on the certificate namespace

The `cert-manager-cluster-rbac` component carries these as a Role and a
ClusterRole for `certificates-system`; bind them to that identity.

In each project control plane, and on the local cluster in `single` discovery
mode, the service needs:

- `tlscertificates`: get, list, watch, patch
- `tlscertificates/status`: update, patch
- `tlscertificates/finalizers`: update
- `namespaces`: get, list, watch

It has no access to Secrets in project control planes and never writes one.
The key pair lives only in the certificate namespace on the cert-manager cluster,
and the finalizer and the periodic sweep remove it with the `TLSCertificate`.

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Go | 1.25+ | https://go.dev/dl |
| Docker | recent | https://docs.docker.com/get-docker |
| kind | v0.20+ | `go install sigs.k8s.io/kind@latest` |
| Task | v3+ | https://taskfile.dev/installation |
| pnpm | v9+ | `npm install -g pnpm` |
| kubebuilder | v4 (reference) | https://book.kubebuilder.io/quick-start |
| gh | any | https://cli.github.com |

kubebuilder is listed as a reference tool — you need it to add new API types after initialization, but not for the initial setup.

---

## Local development

Bootstrap a local kind cluster and deploy the controller:

```bash
task dev:setup
```

This creates a kind cluster (via the shared test-infra Taskfile), builds the controller image, loads it into kind, waits for cert-manager, and applies the dev Kustomize overlay. Expect it to take a couple of minutes on first run.

After making code changes:

```bash
task dev:redeploy
```

This rebuilds the image, loads it into the kind cluster, and cycles the controller pod. Faster than a full `dev:setup`.

Start the Remix UI dev server:

```bash
task ui:dev   # http://localhost:3000
```

The UI connects to the Kubernetes API server using environment variables. Copy `ui/.env.example` to `ui/.env` and configure:

```bash
# Option 1: explicit credentials
<SERVICE>_API_SERVER_URL=https://your-api-server:6443
<SERVICE>_API_CA_FILE=/path/to/ca.crt
<SERVICE>_API_TOKEN_FILE=/path/to/token

# Option 2: local kubeconfig (dev default)
# Leave the URL unset — falls back to .test-infra/kubeconfig automatically
```

Run Chainsaw end-to-end tests:

```bash
task e2e
```

---

## Project structure

```
certificates/
├── cmd/certificates/    # Binary entrypoint
├── api/v1alpha1/               # CRD type definitions (*_types.go)
├── internal/
│   ├── config/                 # Operator config type (kubeconfigPath, etc.)
│   └── controller/             # Reconciler — finalizer, conditions, status
├── internal/webhook/v1alpha1/  # Defaulting + validating webhook
├── config/
│   ├── base/                   # Core manifests (CRD, RBAC, webhook, manager)
│   ├── components/             # Optional overlayable components
│   └── overlays/               # dev and prod environment overlays
├── ui/                         # Remix UI (React + datum-ui, Tailwind)
│   ├── app/routes/             # File-based Remix routes
│   └── app/lib/                # k8s server client, kubeconfig, types
├── test/e2e/                   # Chainsaw test cases
└── hack/
```

---

## Task reference

| Task | What it does |
|------|-------------|
| `task build` | Compile the controller binary |
| `task test` | Run Go tests |
| `task lint` | Run golangci-lint |
| `task generate` | Generate deepcopy and defaulter code |
| `task manifests` | Generate CRD, RBAC, and webhook manifests |
| `task dev:setup` | Create kind cluster and deploy controller |
| `task dev:redeploy` | Rebuild image and cycle the controller pod |
| `task ui:dev` | Start Remix UI at http://localhost:3000 |
| `task ui:build` | Production build of the UI |
| `task ui:type-check` | TypeScript type check |
| `task e2e` | Run Chainsaw e2e tests |

---

## Deploying

The repository includes a GitHub Actions publish workflow that triggers on merge to `main`. It builds and pushes the controller Docker image and Kustomize bundles to `ghcr.io/milo-os/<service-name>`. No additional configuration is needed beyond setting the standard `GITHUB_TOKEN` secret, which Actions provides automatically.
