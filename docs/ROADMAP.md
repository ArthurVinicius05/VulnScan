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
- [x] Source ZIP upload default: 50 MB; queued upload storage default: 100 MB; expanded archive size remains capped at 100 MB.
- [x] Product identity, vision and roadmap consolidated under the VulnScan name; PR #1 merged into `main` on 2026-11-16.

## Priority 1 — trust, privacy and reliability

- [ ] Reproduce the reported account deletion / old-history reappearance scenario in the user's local environment and validate cache/session behavior end to end.
- [x] Add regression tests proving that re-registering with the same email cannot access prior account data.
- [x] Verify sensitive history responses use appropriate private no-store cache controls.
- [ ] Validate deletion behavior across live records, logs and backup-retention disclosures.

## Priority 2 — existing web experience

- [x] Clear account-scoped workspace, report, MFA and upload state on logout, session expiry, account deletion and account changes.
- [x] Remove the remaining legacy Pro label from the workspace footer and avoid implying the website scanner is ready.

- [ ] Reorganize Workspace, Code Analyzer, Website Scanner and Audit History navigation.
- [ ] Move account security, MFA and deletion into functional Settings sections.
- [x] Add an account profile menu with signed-in email, email-verification status, a security/settings shortcut and sign-out.
- [ ] Implement persistent light/dark theme and Portuguese (Brazil)/English localization.
- [ ] Remove duplicated report summaries and improve evidence / remediation hierarchy.
- [x] Remove inactive search and notification controls until they have real functionality; connect Overview, Code Analyzer, Audit History and Settings navigation anchors.

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

## Branch and release workflow

- `main` is the stable integration branch and represents the latest integrated state.
- `develop` is the shared staging branch for upcoming work before it is promoted to `main`.
- Short-lived task branches should be created from `develop`, tested, and merged back into `develop`.
- Promote `develop` to `main` only after the integrated changes pass CI and the maintainer has reviewed the release.
- Emergency fixes may go directly to `main`; sync them back into `develop` afterward.
- A green CI run is necessary but does not by itself mean the product is production-ready.

The initial VulnScan Security Intelligence integration was merged in PR #1. Future changes should follow the branch and release workflow above. Public launch still depends on the external production gates and real-environment validation.
