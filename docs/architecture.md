# Architecture and failure semantics

The Go gateway is the policy-enforcement point. It performs bounded parsing and local recognition before optional FastAPI analysis. Configured actions are applied before content crosses the upstream trust boundary. If contextual analysis is unavailable, local findings remain enforceable; production policies should choose fail-open or fail-closed explicitly before enabling proxy traffic.

Audits count actions and entity types only. Match locations exist transiently for redaction and are removed from API audit representations.
