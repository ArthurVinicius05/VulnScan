# VulnScan Pro

A modular security-auditing platform for authorized website assessments and source-code reviews.

> **Build 0.3.0** — FastAPI + React/TypeScript foundation with safe ZIP inspection, heuristic static analysis, dependency inventory, and a separate container for Python scanner tools. This is an early development build, not a production security scanner.

## Stack
- Frontend: React, TypeScript, Vite, Lucide
- Backend/API: Python, FastAPI, Pydantic Settings
- Static tools: Bandit and Ruff
- Tests: pytest
- Development: Docker Compose

## Run locally

### Docker Compose (recommended for scanner isolation)
Run: `docker compose up --build`

Dashboard: http://localhost:5173  
API docs: http://localhost:8000/docs

The API sends Python archives to a private `scanner-worker` service. The worker is not published to the host and is attached only to an internal Docker network.\n\nOSV scanning is opt-in: set `ENABLE_OSV_SCAN=true` and start Compose with `--profile osv-online`. This starts a separate `osv-worker` with outbound network access for OSV vulnerability matching. The default scanner-worker remains isolated without an external route. Docker networking does not enforce a domain allowlist; production deployments must add an egress firewall/proxy policy if outbound traffic must be restricted to OSV endpoints.

### Run without Docker
Install backend requirements from `backend/requirements.txt`, then run `uvicorn app.main:app --reload` from the backend directory.

For this mode, configure `SCANNER_WORKER_URL` to point to a separately running worker (`uvicorn app.worker:app --port 8001`). API docs: http://localhost:8000/docs

### Frontend
Run `npm install` and `npm run dev` from the frontend directory.

## Current capabilities
- Upload a ZIP source archive (25 MB default limit)
- Reject path traversal, symlinks, encrypted entries, suspicious expansion ratios, and oversized archives
- Identify basic technology markers and list project paths
- Run bounded, read-only heuristic checks on selected source/text files
- Run Bandit and Ruff against a bounded set of Python files in a dedicated scanner-worker container
- Run Gitleaks against a bounded set of text/source files in the worker; secret values are never copied into finding evidence
- Optionally run OSV-Scanner v2.7.1 in a separate, opt-in network-enabled worker to match supported lockfiles against OSV vulnerability data; dependency resolution is disabled
- Keep scanner status separate from findings; an unavailable worker does not prevent heuristic analysis
- Inventory dependency manifests and lockfiles for npm, Python, Rust, Go, Ruby, PHP, Maven, and Gradle without installing packages or making network requests
- Redact detected credential values from finding evidence
- Initial rules cover possible hardcoded credentials, dynamic execution, shell-enabled subprocess calls, pickle deserialization, unsafe YAML loading, HTML injection sinks, and SQL string-building patterns
- Findings include rule ID, severity, confidence, file, line, evidence, and remediation guidance

## Worker isolation controls
The Compose worker:
- Runs as an unprivileged numeric user
- Has a read-only container filesystem and a bounded temporary filesystem mounted with `noexec` and `nosuid`
- Drops Linux capabilities and enables `no-new-privileges`
- Has CPU, memory, and process-count limits
- Is reachable by the API only over a dedicated internal Docker network, with no published host port or external network route
- Applies a request timeout and a 25 MB worker-side upload limit

These controls reduce exposure but are not a complete sandbox or a substitute for host/container-runtime hardening. The API still performs ZIP inspection, heuristics, and dependency inventory itself. Uploaded project code is not intentionally executed; trusted scanner tools process the selected source files.

## Important limitations
- Findings are heuristic indicators, not proof that a vulnerability is exploitable. False positives and false negatives are expected.
- The initial heuristic ruleset is intentionally small and is not a replacement for a professional security review.
- Bandit, Ruff, and Gitleaks run in the isolated worker image. Gitleaks is copied from a pinned upstream image tag; tool status is reported explicitly when a scanner is unavailable or cannot complete.
- OSV-Scanner runs only when explicitly enabled through the `osv-online` profile and `ENABLE_OSV_SCAN=true`. It scans a bounded set of recognized lockfiles, disables package/registry resolution, and queries OSV data. The OSV worker has outbound network access; Docker Compose alone does not restrict destination domains.
- The worker is a dedicated container but is not yet a disposable per-job VM or hardened sandbox; do not expose this development deployment to untrusted public traffic.
- Dependency inventory is metadata-only; OSV vulnerability database matching is not integrated yet. External database access is intentionally not enabled.
- Website scanning, authentication, persistence, AI analysis, and PDF/JSON reporting are not implemented yet.
- This development foundation is not production-hardened.

## Security
Only assess systems you own or are explicitly authorized to test. Treat uploaded archives as untrusted input.

## Roadmap
1. Add egress firewall/proxy allowlisting and integration tests for OSV API access
2. Implement authorized website scanning with strict SSRF protections and scope controls
3. Add evidence-grounded AI explanations via OpenRouter
4. Add reports, audit history, authentication, persistence, and further hardening
