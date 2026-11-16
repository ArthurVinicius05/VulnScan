# VulnScan roadmap

A visão oficial, os limites de escopo e os princípios do produto estão em [PRODUCT_VISION.md](PRODUCT_VISION.md).

## Current foundation
- [x] FastAPI backend and React/TypeScript web application.
- [x] ZIP-based source analysis with safe archive inspection and bounded static checks.
- [x] Isolated Bandit, Ruff and Gitleaks integrations plus dependency inventory.
- [x] Optional OSV scanner in a separate worker.
- [x] Initial passive website assessment with SSRF protections and a separate opt-in worker.
- [x] Account sessions, CSRF, private audit history, email verification, MFA and account deletion.
- [x] Durable analysis queue, quotas, leases, retries and retention controls.
- [x] Reproducible dependency lockfiles, CI, container validation and operational documentation.
- [x] Source ZIP upload default raised from 25 MB to 50 MB; queued upload storage default raised from 50 MB to 100 MB. Expanded archive size remains capped at 100 MB.

## Priority 1 — trust, privacy and reliability
- [ ] Reproduce and resolve the reported account deletion / old-history reappearance scenario.
- [ ] Add regression tests proving that re-registering with the same email cannot access prior account data.
- [ ] Verify sensitive history responses use appropriate private no-store cache controls.
- [ ] Validate deletion behavior across live records, logs and backup-retention disclosures.

## Priority 2 — existing web experience
- [ ] Reorganize Workspace, Code Analyzer, Website Scanner and Audit History navigation.
- [ ] Move account security, MFA and deletion into functional Settings sections.
- [ ] Add a profile menu for account actions, switching accounts and sign-out.
- [ ] Implement persistent light/dark theme and Portuguese (Brazil)/English localization.
- [ ] Remove duplicated report summaries and improve evidence / remediation hierarchy.
- [ ] Make search and notifications either functional or clearly unavailable rather than inert controls.

## Priority 3 — Code Analyzer depth
- [ ] Improve scan coverage and publish independent limits for upload size, expanded size, file count, per-file bytes, total source bytes, tool timeouts and findings.
- [ ] Add a coverage-aware, explainable project Security Score with tests and historical comparisons.
- [ ] Expand language/framework support and explain findings with context-specific examples.
- [ ] Add GitHub repository import with explicit read-only authorization and least-privilege permissions.
- [ ] Add local directory selection in the desktop application.
- [ ] Support comparisons between analysis runs and exportable reports.

## Priority 4 — Website Scanner
- [ ] Expand passive checks for HTTPS/TLS, certificates, headers, cookies, exposed files and configuration.
- [ ] Add safe checks for authentication/session weaknesses with clear coverage limits.
- [ ] Add active checks only as explicit opt-in operations with impact warnings and strict safeguards.
- [ ] Complete SSRF, redirect, DNS rebinding, egress, rate-limit and abuse validation before enabling public scanning.
- [ ] Link website findings to Code Analyzer when source-code investigation could help.

## Priority 5 — desktop and hybrid execution
- [ ] Select a desktop shell and package the shared web experience.
- [ ] Reuse the existing API, account, history and report models.
- [ ] Add secure local directory access and local analysis workers.
- [ ] Define cloud/local/hybrid processing choices with clear privacy and resource disclosures.

## Deferred
- Native mobile application: outside the current product scope.
- Public launch: blocked on production infrastructure, operational and independent security review gates.

## External production gates
1. [ ] Apply and verify host firewall egress allowlisting.
2. [ ] Deploy a real domain and HTTPS/TLS; verify proxy, redirects and secure cookies.
3. [ ] Configure real SMTP and validate SPF, DKIM, DMARC, registration and password recovery.
4. [ ] Configure off-site backups and complete a restore drill in staging.
5. [ ] Configure Alertmanager and centralized logs with retention and redaction.
6. [ ] Run load, abuse and failure-recovery tests in staging.
7. [ ] Complete privacy/terms and LGPD review with real operator details.
8. [ ] Complete an independent security audit / penetration test and remediate findings.
9. [ ] Verify image provenance/signatures and document update and rollback procedures.

CI green does not mean production-ready. The PR remains unmerged until the maintainer has tested the changes and explicitly approved integration.
