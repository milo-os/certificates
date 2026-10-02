# certificates

Certificates, built in. The certificate service issues publicly trusted TLS
certificates for hostnames in Milo project control planes and delivers them as
`kubernetes.io/tls` Secrets beside the request.

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
- The admission webhook enforces these rules and limits who may write
  `TLSCertificates`; see the identity flags below.
- The service does not verify that the project controls the names. Callers
  create a `TLSCertificate` only for names they have already verified. Names
  under `--denied-domain-suffixes` are always rejected, as are public
  suffixes and names whose top-level domain is not a public ICANN domain.
- `dnsNames`, `issuance` and `secretName` are immutable.
- Conditions: `Accepted`, `DNSDelegationReady` (DNS01 only), `Issuing` and
  `Ready`.

## Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--denied-domain-suffixes` | `datumproxy.net,datum.net,datum-staging.net,datumdomains.net,miloapis.com,datumapis.com` | Domains never issued for, including every name beneath them |
| `--allowed-writer-identities` | `system:control@networking.datumapis.com` | Usernames allowed to create, change or delete a `TLSCertificate`. Empty turns off every identity check except the status one |
| `--service-identities` | empty | The service's usernames in project control planes. Only they may write status. Required when the webhook is enabled |
| `--allowed-deleter-identities` | `system:control@platform.miloapis.com`, kube-system namespace-controller and generic-garbage-collector | Extra usernames allowed to delete a `TLSCertificate` and make metadata-only changes, such as removing finalizers: whatever deletes namespaces and collects garbage in project control planes. Milo's controller manager uses `system:control@platform.miloapis.com`. Preview environments use `control@platform.miloapis.com`, without the `system:` prefix, and must override this flag. The kube-system ServiceAccounts apply only to a stock kube-controller-manager |
| `--server-config` | empty | Path to the operator config file |
| `--leader-elect`, `--leader-elect-namespace`, `--health-probe-bind-address` | | Standard manager flags |

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
