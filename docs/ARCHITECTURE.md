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
