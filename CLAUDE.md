# certificates

The Milo certificate service: issues TLS certificates for TLSCertificates in every project control plane through cert-manager. See README.md for the API, flags and permissions.

## Architecture

- **CRD-based**: Uses kubebuilder v4 CRDs (not aggregated API server)
- **Controller-runtime**: Reconciler for lifecycle management
- **Multi-cluster**: Milo's multicluster-runtime provider engages every project control plane
- **Webhook**: validating webhook for names, denied domains and writer identities

## API Group

- Group: `certificates.miloapis.com`
- Version: `v1alpha1`
- Resources: `TLSCertificate`

## Repo Layout

```
certificates/
├── cmd/certificates/main.go  # Binary entrypoint
├── api/v1alpha1/                     # CRD type definitions
├── internal/
│   ├── config/                       # Operator configuration
│   └── controller/                   # Reconcilers
├── config/                           # Kustomize manifests
│   ├── base/                         # Core resources
│   ├── components/                   # Optional components
│   └── overlays/                     # Environment-specific
├── ui/                               # Remix UI (React + datum-ui)
│   ├── app/
│   │   ├── components/AppLayout.tsx  # Sidebar + breadcrumb layout
│   │   ├── lib/                      # k8s.server, kubeconfig.server, types, format
│   │   ├── routes/                   # File-based Remix routes
│   │   └── styles/index.css          # Tailwind + datum-ui theme
│   ├── Dockerfile
│   └── package.json
├── hack/                             # Scripts and boilerplate
└── test/e2e/                         # Chainsaw E2E tests
```

## Verification Commands

```bash
# Controller
task build                    # Build binary
task test                     # Run tests
task lint                     # Run linter
task generate                 # Run code generation
task manifests                # Generate CRD/RBAC/webhook manifests
task dev:setup                # Bootstrap kind cluster + deploy
task dev:redeploy             # Rebuild and redeploy

# UI
task ui:install               # Install UI dependencies (pnpm)
task ui:dev                   # Start dev server at http://localhost:3000
task ui:build                 # Production build
task ui:type-check            # TypeScript check
```
