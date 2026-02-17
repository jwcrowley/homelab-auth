# Suggestions for Improvement

Based on the review of the current stack configuration, the following improvements are recommended:

## 1. Explicit Database Dependency Documentation
The `authentik` application is configured with `postgresql.enabled: false`. While there is a `security/database/cluster.yaml` defining a CloudNativePG cluster, there is no explicit link in the `authentik` Helm values (e.g., `postgresql.external`).
**Recommendation:** Explicitly document or configure the external database connection details in `security/authentik/application.yaml` to decouple the application from implicit assumptions about the database existence.

## 2. Centralized Policy Management
Tetragon runtime policies are currently located in `infra/tetragon/runtime-policy.yaml`. As the number of policies grows, this will become difficult to manage.
**Recommendation:** Create a dedicated policies directory (e.g., `security/policies` or `policies/tetragon`) to organize policies by type (network, process, file) or by application.

## 3. SPIRE Trust Domain Consistency
The trust domain is set to `homelab.internal` in `infra/spire/rotation-config.yaml`. This value is critical for workload identity.
**Recommendation:** Ensure this value is parameterized or clearly documented as a global constant to prevent mismatched configurations between agents and the server.
