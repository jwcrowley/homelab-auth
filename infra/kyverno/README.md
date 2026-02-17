
Install Kyverno:

helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno   --namespace kyverno   --create-namespace

Use to auto-generate default deny NetworkPolicies for new namespaces.
