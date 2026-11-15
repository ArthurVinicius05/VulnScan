# VulnScan roadmap

## Implemented
- [x] FastAPI backend and React/TypeScript frontend.
- [x] Safe ZIP inspection without extracting or executing uploaded source.
- [x] Initial heuristic analysis and isolated Bandit, Ruff and Gitleaks integrations.
- [x] Dependency inventory across supported ecosystems.
- [x] Optional OSV scanner in a separate worker.
- [x] Passive website assessment with SSRF checks and a separate opt-in worker.
- [x] Per-account sessions, CSRF, private audit history and email verification.
- [x] Redis-backed shared rate limiting.
- [x] Durable PostgreSQL queue, leases, retries and idempotent audit history.
- [x] Monthly, concurrent and queued-storage quotas per account; users can cancel queued jobs before execution.
- [x] TOTP MFA, encrypted secrets, recovery codes and replay protection.
- [x] Reproducible Python/npm lockfiles and locked dependency installation.
- [x] SMTP-only egress proxy, internal networks and scanner isolation.
- [x] Automated data retention cleanup and encrypted PostgreSQL backup/restore tooling.
- [x] Prometheus metrics and initial queue/5xx alert rules.
- [x] CI for tests, PostgreSQL integration, backup/restore smoke test, container builds and production Compose validation.

## Remaining before public launch
1. [ ] Dead-letter inspection and administrative recovery controls for repeatedly failed jobs.
2. [ ] Host firewall allowlisting and real deployment egress verification.
3. [x] Pin container images by multi-platform digest and verify registry digests in CI. [ ] Add signature/provenance checks and update/rollback cadence.
4. [x] Add authenticated account deletion for live database records. [ ] Verify deletion across backups/logs and document backup expiry.
5. [ ] Configure Alertmanager, centralized logs and incident-response runbooks.
6. [ ] Complete SSRF/redirect/DNS-rebinding, load, abuse and failure-recovery tests.
7. [ ] Test HTTPS, SMTP deliverability, backup and restore on real production infrastructure.
8. [ ] Complete legal review of privacy/terms and fill operator/contact details.
9. [ ] Independent security audit/penetration test and remediation.

See docs/PRODUCTION_READINESS.md for release gates.
