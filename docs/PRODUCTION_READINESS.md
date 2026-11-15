# Production readiness gate

This checklist is a release gate, not a claim that the current deployment is certified.

## Implemented in the hardening branch

- [x] Production startup validation rejects insecure or incomplete environment configuration.
- [x] PostgreSQL integration tests run against a real PostgreSQL service in CI.
- [x] API and scanner worker use a shared service token.
- [x] Production Compose isolates the scanner worker and keeps website/OSV scanning disabled.
- [x] Durable PostgreSQL analysis queue with row-lock claims, expiring leases, bounded retries and idempotent audit writes.
- [x] Per-account monthly quotas, concurrent-job limits, queued-upload storage caps and user cancellation for jobs that have not started.
- [x] TOTP MFA with encrypted secrets, replay protection, expiring login challenges, one-time recovery codes and session revocation.
- [x] Python hash lockfile and npm lockfile generated in CI; locked installs use pip hashes and npm ci.
- [x] API has no direct internet egress; SMTP is routed through a fixed-upstream proxy that rejects non-public DNS answers.
- [x] Automated retention cleanup for completed/failed jobs, audit records, expired sessions, tokens and MFA challenges.
- [x] Encrypted age-based PostgreSQL backup/restore scripts and a PostgreSQL + age restore smoke test in CI.
- [x] Prometheus HTTP/queue metrics and queue/5xx alert rules; Prometheus UI bound to loopback only.
- [x] CI builds backend, frontend, SMTP proxy, website worker and OSV worker images and validates production Compose.

## Required before public launch

- [ ] Apply and verify host-firewall allowlisting for SMTP proxy destination IPs/ports and DNS; keep website/OSV disabled until SSRF/redirect/DNS-rebinding tests and a separate egress policy pass.
- [ ] Add dead-letter inspection and administrative recovery controls for repeatedly failed jobs.
- [ ] Pin every container image by digest, verify provenance/signatures where available, and document update/rollback cadence.
- [ ] Run load, abuse, concurrency, failure-recovery and backup/restore drills against a production-like environment.
- [ ] Configure Alertmanager notifications, centralized logs, on-call ownership and incident response runbooks.
- [ ] Validate real HTTPS/TLS, SMTP deliverability (SPF/DKIM/DMARC), secret rotation and PostgreSQL restore in the actual hosting environment.
- [x] Add authenticated account deletion for live database records; [ ] verify deletion across off-site backups and logs and document backup expiry/restore implications.
- [ ] Complete privacy/terms review for LGPD, identify the data controller/operator, publish contact details and confirm lawful basis/retention.
- [ ] Commission an independent security review or penetration test, fix findings, and re-run regression/security tests.

## External operator responsibilities

The repository cannot prove the security of a hosting provider, firewall, DNS, TLS certificate, SMTP relay, secrets manager, backup destination or monitoring account. Those controls must be configured and tested in the actual deployment environment before the service accepts untrusted public traffic.

Merging the hardening PR is not a production deployment approval. Keep the service private until every required engineering and operator gate is closed.
