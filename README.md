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
  under `--denied-domain-suffixes` are rejected unless explicitly authorized by
  the reservation-bound managed Connect path below. The DNS01 delegation zone,
  public suffixes and names whose top-level domain is not a public ICANN domain
  are always rejected.
- HTTP01: the consumer serves each entry in `status.challenges` at
  `http://<dnsName>/.well-known/acme-challenge/<token>` with body `<key>`.
- DNS01: the service assigns each name a random delegation target, listed in
  `status.requiredDNSRecords`, which is authoritative. `status.delegationTarget`
  is set only when the spec has a single DNS01 name.
  The name's owner publishes `_acme-challenge.<name>` as a CNAME to it.
  Targets are held per project namespace and name, so recreating a
  TLSCertificate for the same name in the same namespace keeps the target
  and the published CNAME keeps working. Issuance starts only once every
  CNAME resolves to its exact target. Each CNAME must point directly at the
  target. A chain of CNAMEs is not followed, because the check compares only
  the first hop.
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
- `dnsNames`, `issuance` and `managedAuthorization` (including its presence)
  are immutable.
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
`Ready=True`, and treat a change in `status.certificateRevision` as the signal
that the stored certificate has changed. This is the lowercase, 64-character
hex SHA-256 of the leaf certificate's DER bytes, also available as
`CertificateRevision(leaf.Raw)` in the API package. It is not a hash of PEM,
the chain or the private key, and it is not an ordered sequence number.

Before delivery, verify the stored Secret's UID label, exact SAN set, matching
private key and current validity. Compute the leaf fingerprint and require it
to equal the current status revision; a Secret write and a project status write
are not atomic. On mismatch or unavailable status, retry rather than delivering
an obsolete version. Re-read current desired state before acknowledging delivery.
Same-expiry renewals and later-issued shorter-lived rekeys change the revision.
An older or equal-NotBefore candidate cannot replace the stored certificate;
expiry is never used to order replacements. Existing consumers can continue
reading validity dates, but must adopt the revision for reliable rotation.

## Managed Connect authorization

This opt-in path issues one nonwildcard hostname per trusted Connect reservation.
It does not authorize an entire service project or grant a suffix allowlist.
Unconfigured deployments retain protected-domain rejection. When configured, the
managed suffix is also denied to ordinary requests, even if omitted from
`--denied-domain-suffixes`. The DNS01 delegation zone never receives an exception.

Connect owns this reservation in its service-provider Project (not a customer
Project), in the same configured namespace as the TLSCertificate:

The gateway endpoint is independent of VPCs. Its reservation remains scoped to
the customer Project, gateway and metro, not a network or network binding.
`networkUID` and `assignment.vpcRef` are not part of this certificate contract.
Adding, removing or recreating a network binding must preserve the reservation,
TLSCertificate UID, hostname and challenge CNAME; it must not trigger issuance
or rekey. Normal certificate renewal and explicit emergency rekey still apply.

Customer-facing references use resource names. The UID fields below, the
reservation UID in `managedAuthorization`, and the bound certificate UID are
internal service-project identity pins, not customer configuration. Do not
replace these pins with names: deletion and name reuse must not inherit issuance
authority. Connect allocates opaque DNS labels without exposing raw resource
UIDs; Certificates neither allocates hostnames nor derives them from UIDs.

The shared certificate authenticates the gateway hostname for H3/H2 transport.
It does not authorize any VPC or CONNECT-IP stream. Connect and Galactic must
independently authorize each stream, including multiple streams over the same
transport connection. Stream admission and binding revocation do not change
certificate ownership. DNS/TLS requests stay in the service-provider Project;
private keys remain in central issuance infrastructure and authorized cells.

```yaml
apiVersion: connect.datumapis.com/v1alpha1
kind: ConnectEndpoint
metadata:
  name: endpoint
  namespace: connect
  uid: <reservation-uid-assigned-by-api>
spec:
  customerProjectUID: <customer-project-uid>
  gatewayUID: <gateway-uid>
  metro: <metro-id>
  hostname: opaque.connect.example.com
  lifecycle: Active
status:
  certificateRef:
    name: endpoint
    uid: <tlscertificate-uid-assigned-by-api>
```

The tuple and hostname must be immutable in the Connect API. Connect must enforce
hostname uniqueness and prevent reallocation to another tuple. Deletion must
complete before Connect may reactivate the same live gateway identity: remove
the old keys and certificate request and retire its grants before rebinding a
new certificate UID. Network binding churn is not endpoint retirement.
`spec.lifecycle` must equal `Active`; missing or non-Active lifecycle fails closed.
Legacy `status.phase` is ignored and cannot override deletion intent. Ready
conditions are descriptive, not authorization gates: issuance precedes readiness.
Certificates checks the exact reservation UID, nonempty tuple, exact
hostname and certificate name, and rejects a deleting reservation.

Upgrade Certificates to this lifecycle-only reader before removing phase from
the Connect schema and controller. Existing reservations already have lifecycle;
both legacy reservations with phase and new reservations without it are accepted
under the same identity checks. Never fall back to phase when lifecycle is absent
or non-Active. No CLI flag, RBAC or TLSCertificate schema changes are required.

```yaml
apiVersion: certificates.miloapis.com/v1alpha1
kind: TLSCertificate
metadata:
  name: endpoint
  namespace: connect
spec:
  dnsNames: [opaque.connect.example.com]
  issuance: DNS01
  managedAuthorization:
    reservationName: endpoint
    reservationUID: <reservation-uid-assigned-by-api>
```

Provisioning is retry-safe: create the reservation with Active lifecycle, set
`status.certificateRef.name`, create or retrieve the exact TLSCertificate, then
bind its returned UID into `status.certificateRef.uid`. Admission permits an
unbound reservation for bootstrap, but rejects one bound to a different UID.
The controller cannot issue until the UID binding is present. A recreated
certificate has a new UID and cannot inherit an old authorization. Connect
must validate an existing object's spec before binding its UID.

Admission requires the exact configured Connect writer username and Milo's
authenticated `UserInfo.Extra` values `iam.miloapis.com/parent-type: [Project]`
and `iam.miloapis.com/parent-name: [<configured-project-name>]`. Missing,
ambiguous or mismatched context fails closed. This uses the same keys as Milo's
cluster-aware webhook; annotations and object labels are not authentication.
These checks remain enabled when ordinary writer identity restrictions are
disabled. The controller independently compares its discovered cluster name,
namespace, reservation and bound certificate UID before issuance and renewal.

Both components read the reservation directly, without an informer cache, using
a dedicated kubeconfig pinned to the service-provider Project. The request cannot
select this client. Grant its identity (`system:managed-connect-reader@certificates.miloapis.com`)
only `get` on `connect.datumapis.com/connectendpoints` in the configured namespace.
Only the trusted Connect controller may mutate reservation spec or status;
customers must have neither those permissions nor impersonation rights for the
writer or Milo context. The writer is
`system:managed-endpoints@connect.datumapis.com`. The webhook must be installed
with fail-closed admission; enforce these RBAC and authenticated-context
boundaries in the deployment. A reference to a resource customers can write is
not a capability.

Authorization is rechecked at most one minute after the preceding successful
reconcile by default. Missing binding, inactive/deleted reservations and read
failures set `Accepted=False` (`ManagedAuthorizationDenied`), suspend the
cert-manager Certificate and retry. The stored Secret remains untouched. This
does not revoke an issued certificate or terminate existing sessions; Connect
and Galactic own endpoint withdrawal and session revocation. ACME work already
in flight is not an atomic transaction with the reservation API.

Connect publishes the exact challenge CNAME from `status.requiredDNSRecords`;
the existing DNS01 issuer handles delegated TXT. No private key or issuance
Secret is written into either Project. Runtime delivery remains a consumer
responsibility. Prefer named-Secret `get` RBAC. If dynamic names require
namespace-wide `get`, it grants access to every known Secret name in that
namespace; label filtering is not an authorization boundary. No `list` or
`watch` permission is needed for polling. `--certificate-namespace` selects the
entire operator's issuance/storage namespace, not a managed-only subnamespace;
do not deploy a second competing reconciler merely to isolate managed Secrets.

## Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--certificate-namespace` | `certificates-system` | Namespace holding the service-side Certificates and issued Secrets on the cert-manager cluster, and delegation tokens on the local cluster |
| `--http01-cluster-issuer` | empty | cert-manager ClusterIssuer for HTTP01. HTTP01 requests are not accepted when empty |
| `--dns01-cluster-issuer` | empty | cert-manager ClusterIssuer for DNS01. It must follow CNAMEs (`cnameStrategy: Follow`) and be able to write only to the delegation zone |
| `--dns01-delegation-zone` | empty | Zone the DNS01 issuer writes challenge records into. Required with `--dns01-cluster-issuer` |
| `--denied-domain-suffixes` | `datumproxy.net,datum.net,datum-staging.net,datumdomains.net,miloapis.com,datumapis.com` | Protected domains, including every name beneath them; only reservation-bound managed issuance can receive an exception |
| `--managed-connect-kubeconfig` | empty | Dedicated read-only kubeconfig pinned to the trusted service-provider Project |
| `--managed-connect-cluster-name` | empty | Exact Milo Project name in discovery and authenticated admission context |
| `--managed-connect-namespace` | empty | Namespace containing trusted ConnectEndpoints and TLSCertificates |
| `--managed-connect-domain-suffix` | empty | Canonical lowercase managed domain boundary; reservations are still required |
| `--managed-connect-writer-identities` | empty | Exact admission usernames allowed to request managed issuance |
| `--allowed-writer-identities` | `system:control@networking.datumapis.com` | Ordinary writer usernames. Empty disables ordinary identity checks, but not status or managed issuance checks |
| `--service-identities` | empty | The service's usernames in project control planes. Only they may write status. Required when the webhook is enabled |
| `--allowed-deleter-identities` | `system:control@platform.miloapis.com`, kube-system namespace-controller and generic-garbage-collector | Extra usernames allowed to delete a `TLSCertificate` and make metadata-only changes, such as removing finalizers: whatever deletes namespaces and collects garbage in project control planes. Milo's controller manager uses `system:control@platform.miloapis.com`. Preview environments use `control@platform.miloapis.com`, without the `system:` prefix, and must override this flag. The kube-system ServiceAccounts apply only to a stock kube-controller-manager |
| `--max-concurrent-reconciles` | `8` | TLSCertificates reconciled in parallel |
| `--dns01-max-unconfirmed` | `48h` | How long DNS01 renewal continues while delegation lookups fail without a definitive answer |
| `--dns-resolver-address` | empty | `host:port` of the DNS server used for delegation checks. Uses the system resolvers when empty |
| `--server-config` | empty | Path to the operator config file |
| `--leader-elect`, `--leader-elect-namespace`, `--health-probe-bind-address` | | Standard manager flags |

Point the issuers at the ACME staging endpoint in non-production environments;
the service never hardcodes an ACME server.

All five `--managed-connect-*` flags must be supplied together, along with the
DNS01 issuer and delegation zone. They are CLI flags alongside
`--server-config=/config/config.yaml`, not fields in that YAML. Configure both
admission and controller deployments consistently. The reader kubeconfig can
be mounted at `/etc/certificates/managed-connect/kubeconfig.yaml`; its credentials
must not grant project writes or Secret access.

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
| Go | 1.26+ | https://go.dev/dl |
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
└── hack/                       # License header boilerplate for generated code
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

The repository includes a GitHub Actions publish workflow that triggers on merge to `main`. It builds and pushes the controller Docker image and Kustomize bundles to `ghcr.io/milo-os/certificates` (image) and `ghcr.io/milo-os/certificates-kustomize` (bundle). No additional configuration is needed beyond setting the standard `GITHUB_TOKEN` secret, which Actions provides automatically.
