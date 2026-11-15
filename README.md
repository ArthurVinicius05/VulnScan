# VulnScan Pro

A modular security-auditing platform for authorized website assessments and source-code reviews.

> **Foundation build 0.1.0** — initial scaffold with FastAPI, React/TypeScript, and safe ZIP metadata inspection. Active vulnerability scanning is not implemented yet.

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
- Never execute uploaded source code

## Security
Only assess systems you own or are explicitly authorized to test. Uploaded archives are untrusted input. This development foundation is not production-hardened. Website scanning, isolated workers, authentication, persistence, AI analysis, and PDF/JSON reporting are planned.

## Roadmap
1. Static analysis: Semgrep, Bandit, Ruff, Gitleaks, OSV-Scanner
2. Authorized website scanner with SSRF protections
3. Evidence-grounded AI explanations via OpenRouter
4. Reports, audit history, authentication, and hardening
