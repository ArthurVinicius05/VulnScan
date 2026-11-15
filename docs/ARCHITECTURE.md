# Architecture — Production hardening

## Request and analysis flow

Browser -> FastAPI authentication/CSRF and upload limits -> PostgreSQL durable job record -> isolated analysis worker -> isolated scanner worker -> PostgreSQL result/history.

Uploads are persisted in the PostgreSQL job row before the API returns HTTP 202. The analysis worker claims work with row-level locking (\`FOR UPDATE SKIP LOCKED\`), a lease and bounded retries. A worker restart makes expired leases eligible for reprocessing. The raw archive is deleted from the job row after success or terminal failure. Audit history is linked by a unique job ID to prevent duplicate history records after a retry.

## Trust boundaries

- Browser uploads are untrusted and bounded before queue insertion.
- API and analysis worker can access PostgreSQL; the API reaches SMTP only over a dedicated internal network. The SMTP proxy is the sole service attached to the outbound SMTP network and forwards to one pinned, configured public upstream.
- Analysis worker can reach only the isolated scanner service, which requires a shared bearer token.
- Website and OSV scans remain disabled in the production profile until enforceable egress rules and SSRF controls are verified.
- No uploaded project code is executed by the API.

## Quotas

Per-account monthly and concurrent job limits are enforced inside the same transaction that inserts a job. PostgreSQL row locking serializes quota checks for each account. IP-based Redis rate limits remain an additional control, not a replacement for account quotas.

## Remaining production gates

MFA, reproducible dependency lockfiles, network egress enforcement, load/abuse tests, observability, backup/restore drills and an independent security review are still required. See \`docs/PRODUCTION_READINESS.md\`.


## Queue, quotas and retention

Source ZIP submissions create durable PostgreSQL jobs. The API enforces per-account monthly, concurrency and pending-upload-storage limits in the same transaction as enqueueing. The worker claims rows with skip-locked semantics, uses expiring leases and bounded retries, and writes the audit record idempotently. Raw ZIP bytes are cleared on completion or terminal failure. Completed/failed job metadata is retained for 30 days, audit reports for 180 days, and expired sessions, account tokens and MFA challenges are cleaned daily.

## MFA and account protection

TOTP secrets are encrypted with a Fernet key supplied by the operator. Login uses a short-lived, attempt-limited challenge; TOTP steps cannot be replayed, and recovery codes are random one-time values stored only as hashes. Disabling MFA revokes all sessions.

## SMTP-only egress

The API has no direct external network. It reaches a dedicated SMTP proxy over an internal-only network. The proxy resolves one configured SMTP upstream at startup, rejects non-public IP answers, pins the resolved IPs for the process lifetime and forwards only to the configured port. The proxy permits only STARTTLS ports 25, 587 or 2525; implicit TLS/465 is not supported. The host firewall must still restrict the proxy to the relay's current public IPs and port. The API validates that SMTP_TLS_SERVER_NAME exactly matches SMTP_UPSTREAM_HOST. Website and OSV workers remain disabled in production until separate egress/SSRF controls are verified.

## Metrics and recovery

Prometheus scrapes internal HTTP request/latency and database-backed job-state metrics. Its UI is bound to loopback on port 9090 and is not proxied by the public frontend. Queue-backlog and HTTP 5xx alert rules are loaded, but notification delivery requires a separately configured Alertmanager. PostgreSQL backups are encrypted with age and have a restore smoke test in CI; the operator must schedule off-site backups and perform real restore drills.


## Account deletion

Authenticated users can delete their account after confirming the current password and, when enabled, MFA. The API removes queued jobs, saved reports, sessions, account tokens, MFA challenges and recovery codes from the live database. Deletion is rejected while a job is running; users can retry after it finishes. Encrypted off-site backups may retain historical copies until their configured expiry, which must be disclosed and operationally verified.
