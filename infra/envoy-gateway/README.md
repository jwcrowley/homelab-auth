
Install Envoy Gateway:

helm repo add envoy-gateway https://helm.envoygateway.io

helm install envoy-gateway envoy-gateway/gateway-helm   --namespace envoy-gateway-system   --create-namespace

Designed to integrate with SPIFFE/SPIRE for workload mTLS.
