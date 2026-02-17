# Cloudflare Tunnel

Runs `cloudflared` to expose internal services securely without opening inbound ports.

## Prerequisites

1.  **Cloudflare Account**: You need a domain on Cloudflare.
2.  **Tunnel Created**: Create a tunnel in the Zero Trust Dashboard.

## Setup

1.  Get your Tunnel Token from the Cloudflare Dashboard.
2.  Create the secret in the `infra` namespace:

```bash
kubectl create secret generic cloudflared-token \
  --namespace infra \
  --from-literal=token=<YOUR_TOKEN>
```

3.  Apply this directory (managed via ArgoCD).

## Networking

This deployment uses the "Cluster-side ingress" model (or ad-hoc proxy).
*   It points to the Ingress Controller (Traefik) Service `http://traefik.kube-system.svc.cluster.local:80`.
*   You must configure your Public Hostname in the Cloudflare Dashboard to point to this Tunnel.
    *   Service: `http://traefik.kube-system.svc.cluster.local:80`
