# VulnScan Pro

A modular security-auditing platform for authorized website assessments and source-code reviews.

> **Build 0.2.0** — FastAPI + React/TypeScript foundation with safe ZIP inspection and an initial heuristic static-analysis engine. This is an early development build, not a production security scanner.

## Stack
- Frontend: React, TypeScript, Vite, Lucide
- Backend: Python, FastAPI, Pydantic Settings
- Tests: pytest
- Development: Docker Compose

## Run locally

### Backend
```bash
cd backend
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
API docs: http://localhost:8000/docs

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Dashboard: http://localhost:5173

## Current capabilities
- Upload a ZIP source archive (25 MB default limit)
- Reject path traversal, symlinks, encrypted entries, suspicious expansion ratios, and oversized archives
- Identify basic technology markers and list project paths
- Run bounded, read-only heuristic checks on selected source/text files
- Run Bandit and Ruff against a bounded set of Python files when the tools are installed
- Show scanner availability/status separately from findings
- Inventory dependency manifests and lockfiles for npm, Python, Rust, Go, Ruby, PHP, Maven, and Gradle without installing packages or making network requests
- Redact detected credential values from finding evidence
- Initial rules cover possible hardcoded credentials, dynamic execution, shell-enabled subprocess calls, pickle deserialization, unsafe YAML loading, HTML injection sinks, and SQL string-building patterns
- Findings include rule ID, severity, confidence, file, line, evidence, and remediation guidance
- Uploaded source code is never executed

## Important limitations
- Findings are heuristic indicators, not proof that a vulnerability is exploitable. False positives and false negatives are expected.
- The initial heuristic ruleset is intentionally small and is not a replacement for a professional security review.
- Bandit and Ruff are invoked as trusted scanner processes with timeouts and bounded temporary input. This first integration runs inside the API container; it is not yet a dedicated sandboxed worker.
- The analyzer reads only selected text extensions, with per-file and aggregate byte limits.
- Dependency inventory is metadata-only; vulnerability database matching (for example OSV) and secret scanning with Gitleaks are not integrated yet. External database access is intentionally not enabled.
- Website scanning, isolated workers, authentication, persistence, AI analysis, and PDF/JSON reporting are not implemented yet.
- This development foundation is not production-hardened.

## Security
Only assess systems you own or are explicitly authorized to test. Treat uploaded archives as untrusted input.

## Roadmap
1. Expand static analysis and move scanner execution into dedicated isolated workers
2. Authorized website scanner with strict SSRF protections and scope controls
3. Evidence-grounded AI explanations via OpenRouter
4. Reports, audit history, authentication, persistence, and hardening
