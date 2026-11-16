# VulnScan — Product vision

## Product definition

VulnScan is a security-intelligence platform for software developers and cybersecurity practitioners at every experience level. It analyzes source projects and authorized websites, identifies weaknesses and improvement opportunities, explains why each finding matters, and teaches users how to remediate issues.

**Product promise:** Analyze. Secure. Learn. Improve.

The product is not limited to beginners. Beginners should receive clear explanations and guided remediation, while experienced developers and security professionals should be able to inspect evidence, coverage, severity, references, and technical details.

## Supported product surfaces

The near-term product scope is:
- **Web application:** primary experience, accessible through a browser.
- **Desktop application:** planned companion application, reusing the shared API and analysis engines where appropriate. Desktop capabilities can include selecting local project directories without requiring the user to create a ZIP manually.

A mobile application is explicitly out of the current roadmap. The responsive web experience may remain usable on mobile browsers, but native mobile development is not a current deliverable.

## Core tools

### Code Analyzer

The Code Analyzer should accept projects through multiple entry points:
1. ZIP upload — current implemented input.
2. Local directory selection — planned for the desktop application.
3. GitHub repository — planned read-only integration, with explicit authorization and least-privilege access.

The analysis should cover, within documented and measurable limits:
- Security vulnerabilities and insecure coding patterns.
- Bugs and suspicious implementation patterns.
- Code quality and maintainability.
- Project structure and architecture.
- Performance and optimization opportunities.
- Dependency inventory and known vulnerable dependencies.
- Explanations, evidence, severity, confidence, references, and actionable remediation examples.

Uploaded or imported project code must remain untrusted data. The platform must not execute submitted project code as part of ordinary static analysis. Scanner tools must run in isolated, resource-limited workers.

A larger upload limit must not be presented as proof that every byte or every file is analyzed. Upload size, expanded archive size, file count, per-file scan size, total source bytes scanned, tool timeouts, and findings limits are separate controls. The current heuristic analyzer has a 512 KiB per-file ceiling and a 5 MiB total source-byte ceiling; integrated tools have their own coverage and timeout limits. These ceilings must be reviewed and raised only with resource profiling and regression tests. Reports must disclose partial coverage and truncation.

### Website Scanner

The Website Scanner assesses only targets the user owns or is explicitly authorized to test. Its planned coverage includes:
- HTTPS, TLS certificate validity, and redirect behavior.
- HTTP security headers and cookie attributes where observable.
- Exposed files, directories, metadata, and accidental disclosures.
- Insecure server and application configuration.
- Common web vulnerability indicators.
- Authentication and session weaknesses that can be assessed safely.
- Evidence, risk explanations, and prioritized remediation guidance.

Scanning must use explicit authorization, strict SSRF defenses, bounded requests, safe request methods by default, controlled redirects, rate limits, and enforceable network egress. Active or intrusive tests must be separate opt-in checks with clear impact warnings and stronger safeguards. The current passive scanner is not a full penetration test and must not claim to find every vulnerability.

The Website Scanner and Code Analyzer should recommend each other when useful, but neither tool should require the other. A website finding may link to a source-code investigation when the underlying issue likely resides in the application code.

## Security Score

A project-level Security Score (0–100) is planned as an educational progress indicator, not a guarantee of security or a certification.

The score must be reproducible and explainable. Its model should account for:
- Finding severity and confidence.
- Exposure and potential impact where evidence supports it.
- Analysis coverage and unavailable scanners.
- Resolved, accepted, and outstanding findings.
- Changes compared with the previous analysis.

The interface must show the score's methodology, coverage, and uncertainty. Missing findings or incomplete coverage must never automatically produce a perfect score. Scores should be comparable only when the analysis profiles and scoring model are compatible. Users should see progress over time and the concrete actions that can improve the score.

## Learning-first experience

Every meaningful finding should answer:
1. What was detected?
2. Where is the evidence?
3. Why does it matter?
4. How could it be abused or cause harm?
5. How can it be corrected?
6. How can the user verify the correction?

Recommendations should be prioritized and adapted to the selected language/framework when enough context exists. The platform should distinguish confirmed facts, heuristics, and suggestions; it must not describe a heuristic as a proven exploit.

## Architecture direction

Keep the current Python/FastAPI backend and React/TypeScript web client as the initial shared foundation. The desktop application should reuse the API, identity, history, report model, and analysis engines rather than becoming a separate product. A desktop shell such as Tauri can be evaluated when the desktop milestone begins.

Support two execution modes over time:
- **Cloud processing:** useful for heavier analysis and machines with limited resources.
- **Local processing:** useful for privacy, offline workflows, and selecting local folders.

A hybrid model is the long-term direction. Local processing must be optional and its resource requirements explicit. The project should not require a low-spec computer to run every heavy scanner locally.

## Product experience

The interface should provide:
- Clear navigation for Workspace, Code Analyzer, Website Scanner, Audit History, and Settings.
- A functional profile menu for profile/account actions, switching accounts, and sign-out.
- Settings organized into General, Account, Security, Privacy, Notifications, and Analysis.
- Light and dark themes.
- Portuguese (Brazil) and English initially, with language preference persisted.
- Clear reports without duplicated summaries and with expandable technical details.
- Project-level history, comparison between analyses, and progress tracking.
- Exportable reports and useful notifications when analyses finish.

## Current implementation boundaries

The current main branch contains an initial web application, ZIP-based static source analysis, account/session controls, audit history, isolated scanner integrations, and an optional passive website assessment worker. The initial Security Intelligence hardening and product documentation were integrated through PR #1. The website scanner and OSV integration remain disabled in the production profile until their network egress and security controls are validated.

Local-directory import, GitHub repository import, desktop packaging, a complete score model, full settings/navigation, localization, and the complete Website Scanner experience are roadmap work. Documentation of these goals does not mean they are already implemented.

## Delivery principles

1. Fix account isolation, deletion, and data privacy before expanding public access.
2. Make existing navigation and settings truthful and functional.
3. Improve analyzer coverage and report transparency before increasing resource limits aggressively.
4. Implement Security Score only after its methodology and tests are defined.
5. Enable website scanning only after SSRF, egress, rate-limit, and safe-test controls are independently validated.
6. Add local-directory and GitHub inputs with explicit trust boundaries and tests.
7. Build the desktop application on top of the shared platform.
8. Keep the pull request unmerged until the maintainer has tested and explicitly approved it.
