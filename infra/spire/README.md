
Deploy SPIRE via Helm:

helm repo add spire https://spiffe.github.io/helm-charts
helm install spire spire/spire   --namespace spire-system   --create-namespace

Used for workload identity between Authentik, Postgres, and internal services.
