
Install Gatekeeper:

helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper gatekeeper/gatekeeper   --namespace gatekeeper-system   --create-namespace

Use to enforce:
- No privileged pods
- Required NetworkPolicies
- No hostNetwork usage
