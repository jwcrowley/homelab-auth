
Flux GitOps Alternative

Install:

curl -s https://fluxcd.io/install.sh | sudo bash

flux bootstrap github   --owner=<your-user>   --repository=homelab-prod   --branch=main   --path=clusters/prod

Allows comparison vs ArgoCD app-of-apps.
