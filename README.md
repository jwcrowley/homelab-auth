# Homelab Production Identity Stack (v5)

This repository contains the configuration for a production-grade identity and security stack for a Kubernetes homelab. It integrates user identity (Authentik), workload identity (SPIRE), and runtime enforcement (Tetragon/Cilium).

## Architecture Overview

The stack is designed to provide Zero Trust principles at multiple layers:

1.  **User Identity**: Managed by **Authentik**, providing SSO and centralized authentication for all ingress services.
2.  **Workload Identity**: Managed by **SPIRE** (SPIFFE Runtime Environment), issuing short-lived X.509 certificates to workloads for mTLS and authentication.
3.  **Runtime Security**: Managed by **Tetragon** (via Cilium), enforcing process execution and network policies at the kernel level using eBPF.

## Directory Structure

*   `apps/`: User-facing applications (e.g., example apps).
*   `infra/`: Infrastructure components (Cilium, SPIRE, Tetragon, ArgoCD).
*   `security/`: Security-specific configurations (Authentik, Databases, Policies).
*   `bootstrap/`: Initial cluster bootstrap scripts (if applicable).

## Components

### Identity Provider (Authentik)

Located in: `security/authentik`

Authentik is deployed via ArgoCD and handles user authentication.
*   **Database**: Uses CloudNativePG (`security/database`).
*   **Ingress**: protect services via Traefik middleware or forward auth.

### Workload Identity (SPIRE)

Located in: `infra/spire`

SPIRE issues identities to workloads based on k8s selectors.
*   **Trust Domain**: `homelab.internal`
*   **Agent**: Runs as a DaemonSet on every node.
*   **Server**: Central authority for minting SVIDs.

**Key Features:**
*   Automated certificate rotation (`rotation-config.yaml`).
*   Workload attestation via Kubernetes projected service account tokens.

### Runtime Security (Tetragon)

Located in: `infra/tetragon`

Tetragon provides deep visibility and enforcement.
*   **Policies**: Defined in `security/policies/tetragon/block-shell.yaml`.
*   **Enforcement**: Can sigkill processes that violate policies (e.g., unexpected shell execution).

## Getting Started

### Prerequisites

*   Kubernetes Cluster (k3s/Talos recommended for Cilium compatibility).
*   Cilium installed as CNI.
*   Helm & ArgoCD.

### Deployment

The stack is managed via GitOps (ArgoCD).

1.  **Bootstrap Infrastructure**:
    Apply the infrastructure applications first.
    ```bash
    kubectl apply -f infra/
    ```

2.  **Deploy Security Services**:
    Once infra is healthy, deploy the security layer.
    ```bash
    kubectl apply -f security/
    ```

## Usage Guides

### Onboarding a Service to SPIRE

Add a `SpiffeID` CRD or equivalent registration entry mapping the service account to a SPIFFE ID.
See `apps/example-spiffe-enabled-deployment.yaml` (if available) for reference.

### rotating SPIRE Certificates

Certificates are rotated automatically by the SPIRE Agent based on `default_svid_ttl` (configured to 1h). No manual intervention is required unless the root CA is expiring.

### Applying Tetragon Policies

To block specific behaviors (e.g., shell access in production pods):

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-shell
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "/bin/sh"
      action: Post
```

Apply with `kubectl apply -f <policy.yaml>`.
