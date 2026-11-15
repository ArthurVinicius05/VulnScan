# Production readiness gate

This checklist is a release gate, not a claim that the current deployment is certified.

## Implemented in the hardening PR

- [x] Production startup validation rejects insecure or incomplete environment configuration.
- [x] PostgreSQL integration checks run against a real PostgreSQL service in CI.
- [x] API and scanner worker use a shared service token.
- [x] Production Compose isolates the scanner worker and keeps website/OSV scanning disabled.
- [x] CI validates backend tests, frontend build, production Compose and container builds.

## Required engineering work before public launch

- [x] Replace synchronous request-bound source scans with a PostgreSQL-backed durable queue, row-lock claims, expiring leases, bounded retries and idempotent history writes. Cancellation is still pending.
- [x] Enforce per-account monthly and concurrent analysis quotas transactionally in PostgreSQL. Storage retention and account-level cleanup policies remain pending.
- [ ] Implement MFA enrollment, recovery codes, login challenge and session revocation.
- [ ] Commit reproducible Python and npm lockfiles; pin container images by digest and verify update automation.
- [ ] Apply enforceable egress policy (firewall or controlled proxy) for every service with network access; add SSRF/redirect/DNS-rebinding integration tests.
- [ ] Add load, abuse, concurrency, backup/restore and disaster-recovery tests.
- [ ] Add structured audit logs, metrics, alerting, retention/deletion workflows and incident response procedures.
- [ ] Run an independent security review and validate deployment behind real HTTPS with SMTP deliverability controls.

## External operator responsibilities

The repository cannot prove the security of a hosting provider, firewall, DNS, TLS certificate, SMTP relay, secrets manager, backup destination or monitoring account. Those controls must be configured and tested in the actual deployment environment before the service accepts untrusted public traffic.

The merge of this PR is not a production deployment approval. Keep the service private until every required engineering and operator gate is closed.
