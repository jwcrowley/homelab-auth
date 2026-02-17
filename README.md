# Homelab Production Identity Stack (v5)

This repository contains the configuration for a production-grade identity and security stack for a Kubernetes homelab. It integrates user identity (Authentik), workload identity (SPIRE), and runtime enforcement (Tetragon/Cilium).

## Architecture Overview

## Architecture Overview

The stack is designed to provide Zero Trust principles at multiple layers:

```mermaid
graph TD
    User((User)) -->|HTTPS| Ingress[Traefik Ingress]
    Ingress -->|Auth Request| Authentik[Authentik IdP]
    Authentik -->|Allow/Deny| Ingress
    Ingress -->|Traffic| Service[Application Service]
    
    subgraph "Workload Identity (SPIRE)"
    SpireServer[SPIRE Server] <-->|Attestation| SpireAgent[SPIRE Agent]
    SpireAgent -->|Issue SVID| Service
    end
    
    subgraph "Runtime Security (Tetragon)"
    Tetragon[Tetragon] -->|eBPF Hooks| Kernel((Linux Kernel))
    Kernel -->|Enforcement| Service
    end
```

1.  **User Identity**: Managed by **Authentik**, providing SSO and centralized authentication for all ingress services.
2.  **Workload Identity**: Managed by **SPIRE** (SPIFFE Runtime Environment), issuing short-lived X.509 certificates to workloads for mTLS and authentication.
3.  **Runtime Security**: Managed by **Tetragon** (via Cilium), enforcing process execution and network policies at the kernel level using eBPF.

## Directory Structure

*   `cluster/`: Bootstrap configurations and ArgoCD Application definitions (including Networking).
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
    *   **Note**: This is an separate internal logical identifier for SPIFFE IDs (e.g., `spiffe://homelab.internal/ns/default/sa/my-app`). It does **NOT** need to be a real DNS domain or public domain. It is an arbitrary string that defines the security boundary of the mesh.
*   **Agent**: Runs as a DaemonSet on every node.
*   **Server**: Central authority for minting SVIDs.

**Key Features:**
*   Automated certificate rotation (`rotation-config.yaml`).
*   Workload attestation via Kubernetes projected service account tokens.

```mermaid
sequenceDiagram
    participant W as Workload (Pod)
    participant A as SPIRE Agent
    participant S as SPIRE Server
    participant K as K8s API

    Note over W,A: Node Attestation
    A->>S: Node Attestation Request
    S->>K: Validate Node
    S-->>A: Issue Agent SVID

    Note over W,S: Workload Attestation
    W->>A: Request SVID (Socket)
    A->>K: Validate Pod Selector (SA, Labels)
    A-->>W: Mint Workload SVID (X.509)
    W->>W: Mount SVID to memory
```

### Runtime Security (Tetragon)

Located in: `infra/tetragon`

Tetragon provides deep visibility and enforcement.
*   **Policies**: Defined in `security/policies/tetragon/block-shell.yaml`.
*   **Enforcement**: Can sigkill processes that violate policies (e.g., unexpected shell execution).

```mermaid
flowchart LR
    Policy[YAML Policy] -->|Apply| K8s[Kubernetes API]
    K8s -->|Config| TetragonDaemon[Tetragon Daemon]
    TetragonDaemon -->|Load| eBPF[eBPF Program]
    
    subgraph Kernel Space
    eBPF -->|Hook| Syscall[sys_execve]
    end
    
    subgraph User Space
    Shell[bash] -->|Call| Syscall
    end
    
    eBPF -- Match '/bin/sh' --> Kill[SIGKILL]
    Kill -.-> Shell
```

### Remote Access (Netbird)

Located in: `cluster/networking`

Netbird provides a secure peer-to-peer overlay network for remote access.
*   **Deployment**: Managed via ArgoCD (`cluster/networking/netbird.yaml`).
*   **Integration**: Deployed to `networking` namespace.

**Self-Hosted Architecture**:
This deployment is fully self-hosted. It replaces the Netbird.io SaaS.
*   **Management**: Stores configuration and peer state (Internal).
*   **Signal**: Facilitates peer-to-peer connection negotiation (Internal).
*   **Relay (TURN)**: Relays traffic when P2P fails (Internal/Coturn).
*   **Dashboard**: Web UI for management (Internal).
*   **External Dependency**: None (except for public DNS/Ingress as noted below).

**Cloudflare Tunnel Integration (Hybrid)**:

To maximize both security and performance, this stack uses a **Hybrid Networking** model.

```mermaid
graph TD
    Peer((Remote Peer)) --> Router[Your Router]
    
    subgraph "Secure Entry (TCP)"
    Router -->|Tunnel:443| CFTunnel[Cloudflare Tunnel]
    CFTunnel -->|Proxy| Ingress[Traefik Ingress]
    Ingress -->|Mgmt/Signal| NetbirdAPI[Netbird Components]
    end
    
    subgraph "High-Speed Data (UDP)"
    Router -->|Port Forward:3478| Coturn[Netbird Relay / Coturn]
    end
    
    Peer -.->|Auth & Signaling| CFTunnel
    Peer -.->|VPN Traffic Relay| Coturn
```

*   **Management Plane (Cloudflare Tunnel)**: All control traffic (Dashboard, Management API, and gRPC Signal) goes through the Cloudflare Tunnel. This hides your public IP and provides DDoS protection for the "brains" of the network.
*   **Data Plane (UDP Port Forwarding)**: Netbird uses WireGuard for peer-to-peer traffic. If peers cannot connect directly, they use the **Relay (TURN)** server. This server uses UDP port 3478. Because Cloudflare Tunnel (standard) does not support UDP traffic with the performance required for a VPN, you **MUST** forward UDP port 3478 on your router directly to the cluster. This ensures your VPN remains fast and reliable.

**Configuration Required**:
You **MUST** configure your public domain in `cluster/networking/netbird.yaml`.
*   **Real Domain Required**: Because this stack uses Let's Encrypt with HTTP-01 challenges (`acme-clusterissuer.yaml`), you cannot use a local domain (like `.local`). You must use a **real public domain** (e.g., `netbird.yourdomain.com`) that resolves to your cluster's Ingress/LoadBalancer IP.
*   **How to Configure**: Edit `cluster/networking/netbird.yaml` and uncomment/update the `helm.values` section with your domain.

## Getting Started

### Prerequisites

*   Kubernetes Cluster (k3s/Talos recommended for Cilium compatibility).
*   Cilium installed as CNI.
*   Helm & ArgoCD.

### Deployment Guide

This stack is managed via a GitOps "App-of-Apps" pattern using ArgoCD.

### 1. Prerequisites

Before bootstrapping, ensure your cluster has:
*   **CNI**: [Cilium](https://cilium.io/) installed and healthy (required for Tetragon).
*   **Storage**: A default storage class configured (e.g., Local Path Provisioner, Longhorn) for Postgres.
*   **Secrets**:
    *   **SOPS**: An age/PGP key for decrypting repository secrets.
    *   **Cloudflare**: A `cloudflared-token` in the `infra` namespace:
      ```bash
      kubectl create secret generic cloudflared-token --namespace infra --from-literal=token=<token>
      ```

### 2. Bootstrapping (Stage 1)

Apply the foundational namespaces and the root ArgoCD application:

```bash
# 1. Create the base namespaces
kubectl apply -f cluster/infra/namespaces.yaml

# 2. Deploy the root ArgoCD application
kubectl apply -f cluster/infra/argocd-apps.yaml
```

This will automatically deploy:
*   `cert-manager` (for automated TLS)
*   `cloudnative-pg` (Postgres operator)
*   `external-secrets` (if using vault/asm/etc.)

### 3. Deploying the Stack (Stage 2)

Once the core infrastructure is healthy, apply the remaining stack layers:

```bash
# Deploy Infra (SPIRE, Tetragon)
kubectl apply -k cluster/infra/

# Deploy Security (Authentik, Policies)
kubectl apply -k cluster/security/

# Deploy Networking (Netbird, Ingress)
kubectl apply -k cluster/networking/
```

### 4. Post-Deployment Configuration

1.  **Netbird Domain**: Edit `cluster/networking/netbird.yaml` and set your public domain.
2.  **Hybrid Networking**: Forward UDP Port `3478` on your router to the cluster LoadBalancer IP for Netbird Relay performance.
3.  **Trust Domain**: Ensure your SPIRE trust domain (`homelab.internal`) matches in `infra/spire/rotation-config.yaml`.

## Verification

Monitor the deployment in the ArgoCD UI or via CLI:
```bash
kubectl get pods -A
kubectl get tracingpolicy -A
```

## SSO Integration Guide

This stack leverages **Authentik** as a central Identity Provider (IdP) to provide Single Sign-On (SSO) for internal applications.

### SSO Flow (ForwardAuth)

```mermaid
sequenceDiagram
    participant U as User
    participant T as Traefik Ingress
    participant A as Authentik Outpost
    participant S as App Service

    U->>T: Request https://myapp.example.com
    T->>A: ForwardAuth Request
    alt Session Valid
        A-->>T: 200 OK + User Headers
        T->>S: Forward Request
        S-->>U: App Content
    else Session Invalid
        A-->>T: 401 Unauthorized / Redirect
        T-->>U: Redirect to Authentik Login
        U->>A: Login (OIDC/LDAP/MFA)
        A-->>U: Set Session Cookie + Redirect back
    end
```

### How to Onboard an Application

To protect a new internal service with SSO, follow these steps:

1.  **Create Provider**: In the Authentik UI, go to `Resources -> Providers` and create a **Proxy Provider**.
    *   **Authorization flow**: default-provider-authorization-implicit-consent
    *   **External host**: `https://myapp.example.com`
2.  **Create Application**: Go to `Resources -> Applications` and create an application linked to the Provider.
3.  **Define Middleware (Traefik)**: Ensure a `Middleware` resource exists in Kubernetes pointing to your Authentik Outpost:
    ```yaml
    apiVersion: traefik.io/v1alpha1
    kind: Middleware
    metadata:
      name: authentik-sso
      namespace: security
    spec:
      forwardAuth:
        address: http://authentik-outpost-embedded.security.svc.cluster.local:9000/outpost.goauthentik.io/auth/traefik
        trustForwardHeader: true
        authResponseHeaders:
          - X-authentik-username
          - X-authentik-groups
    ```
4.  **Protect the Ingress**: Add the middleware annotation to your application's Ingress:
    ```yaml
    annotations:
      traefik.ingress.kubernetes.io/router.middlewares: security-authentik-sso@kubernetescrd
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
