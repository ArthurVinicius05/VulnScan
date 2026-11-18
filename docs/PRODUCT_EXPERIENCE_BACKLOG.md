# VulnScan — Product Experience Backlog

This backlog records the product feedback collected during the first hands-on review of the `develop` build. It is intentionally separate from production-readiness/security gates. Items checked below are implemented in the `feat/product-experience-refresh` draft PR; they are not yet merged into `develop`.

## P0 — Core navigation and information architecture
- [x] Replace the single long workspace page with dedicated routes: Overview, Website Scanner, Code Analyzer, Audit History, Settings, and Profile.
- [x] Make sidebar navigation change the route/view instead of scrolling to anchors.
- [x] Keep Overview focused on summary metrics, recent activity, and clear next actions.
- [x] Move account security/MFA and preferences into Settings sub-pages or clearly separated sections.
- [x] Move account identity to a compact profile destination/menu; do not show the full email persistently in the sidebar.
- [x] Add responsive route transitions.
- [x] Move keyboard focus to the main content after in-app route changes.
- [ ] Add keyboard-navigation and screen-reader acceptance tests.

## P0 — Make existing workflows understandable
- [x] Explain required server-side configuration when MFA cannot be initialized; never ask users to invent or paste arbitrary secrets.
- [ ] Keep MFA setup guided: show authenticator enrollment, verification, recovery-code handling, and clear failure/retry states.
- [ ] Make audit details a distinct report view, not a duplicate copy of the current scan result.
- [x] Add a report export action (JSON first; evaluate PDF/HTML after format and privacy review).
- [ ] Improve empty, loading, partial-coverage, failed, and success states throughout the application.

## P0 — Website Scanner
- [x] Integrate the existing passive website scanner with a dedicated UI and explicit authorization confirmation (local worker profile required).
- [x] Display HTTP status, TLS details when available, redirect chain, findings, and scan limitations.
- [ ] Add an explicit normalized-scope summary to the result view.
- [ ] Preserve the isolated worker, public-IP validation, DNS pinning, redirect revalidation, strict timeouts, and bounded response sampling.
- [ ] Add integration tests for the UI/API/worker path and SSRF edge cases before enabling this feature in any public deployment.
- [ ] Keep the production feature flag disabled until independent egress and SSRF validation is complete.

## P1 — Upload and analysis capabilities
- [x] Raise the source ZIP upload ceiling to 100 MB consistently across frontend, API configuration, Compose defaults, and examples.
- [ ] Keep expanded archive size, file-count, queue-storage, time, and worker resource limits independent from compressed upload size.
- [x] Explain accepted inputs: source-code ZIP archives are supported; Windows installers (.exe/.msi) are not source-code archives.
- [ ] Evaluate a separate static binary/package metadata analysis workflow rather than trying to execute installers.
- [ ] Improve progress reporting, cancellation feedback, and report navigation after a scan completes.

## P1 — Localization
- [ ] Expand language selection beyond Portuguese and English to Spanish, Russian, Simplified Chinese, and Japanese.
- [ ] Translate the complete interface, validation messages, reports, accessibility labels, and date/number formatting for each supported locale.
- [ ] Do not advertise a locale as supported until all user-facing strings have a reviewed translation.

## P1 — Visual system
- [ ] Establish a consistent typography scale, spacing scale, content width, surface hierarchy, and semantic color tokens.
- [ ] Improve density and alignment; avoid tiny text and inconsistent gaps.
- [ ] Redesign cards, forms, upload dropzones, report findings, history rows, dialogs, and responsive navigation.
- [ ] Add subtle, reduced-motion-aware transitions and clear hover/focus/disabled states.
- [ ] Verify both light and dark themes across every route.

## P2 — Release readiness
- [ ] Add end-to-end tests for registration/login, MFA, upload, analysis, report export, history comparison, settings, and website scanning.
- [ ] Test mobile/tablet layouts, keyboard navigation, screen-reader labels, and localization overflow.
- [ ] Complete the existing production checklist (HTTPS, SMTP, PostgreSQL, backups, alerting, egress/SSRF, privacy/LGPD, load testing, and independent security review).

## Release policy
- Work in feature branches and open reviewable PRs against `develop`.
- Do not merge into `main` without explicit approval.
- A green CI run is necessary but does not replace manual acceptance testing or production-readiness evidence.
