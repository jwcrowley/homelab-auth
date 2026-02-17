
Install Cilium with Hubble:

helm repo add cilium https://helm.cilium.io/

helm install cilium cilium/cilium   --namespace kube-system   --set hubble.enabled=true   --set hubble.relay.enabled=true   --set hubble.ui.enabled=true

Provides L7 visibility and zero-trust network enforcement.
