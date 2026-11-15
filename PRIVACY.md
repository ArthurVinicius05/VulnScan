# Privacy notice — draft

> **This is a template, not a legally reviewed privacy policy.** Before public launch, the operator must identify the controller, fill the contact channel, confirm lawful bases, subprocessors, cross-border transfers and LGPD requirements with qualified counsel.

## Operator and contact

- Controller/operator: **[LEGAL NAME / ORGANIZATION]**
- Contact for privacy requests: **[PRIVACY CONTACT EMAIL]**
- Hosting region: **[REGION / COUNTRY]**
- Effective date: **[DATE]**

## Data processed

VulnScan may process:
- Account email address and password hash (passwords are not stored in plaintext).
- Session, email-verification, password-reset and MFA challenge token hashes.
- Encrypted TOTP secret and hashes of one-time recovery codes.
- Uploaded source-code ZIP files while an analysis is pending or running.
- Analysis metadata, findings, dependency inventory and generated reports.
- Operational logs, request metadata, security events and service metrics.
- SMTP delivery metadata needed to send account confirmation and password-reset messages.

Do not upload production secrets, credentials, personal data or source code unless you are authorized and have assessed whether the service is appropriate for that data.

## Purposes

Data is used to provide account authentication, authorized security analysis, report history, abuse prevention, service reliability, security monitoring and account communications.

## Retention defaults

- Raw uploaded archives are deleted when the analysis completes or reaches terminal failure.
- Completed/failed job metadata is retained for 30 days.
- Audit reports are retained for 180 days.
- Expired sessions, account tokens and MFA challenges are purged by scheduled maintenance.
- PostgreSQL backups are encrypted with age; backup retention and off-site storage are controlled by the deployment operator and must be documented separately.
- Infrastructure logs and third-party SMTP/hosting logs may have separate retention periods set by those providers.

The operator must configure actual retention values and publish them here before launch.

## Security

The application uses password hashing, HttpOnly session cookies, CSRF validation, TOTP MFA with encrypted secrets, one-time recovery codes, isolated scanner workers, upload limits, account quotas and internal service networks. These safeguards reduce risk but cannot guarantee absolute security.

## Service providers and transfers

The deployment may use a hosting provider, SMTP relay, DNS provider, backup storage and monitoring services. **[LIST PROVIDERS, PURPOSES, LOCATIONS AND TRANSFER DETAILS BEFORE LAUNCH.]**

## Data subject requests

For access, correction, deletion or other privacy requests, contact **[PRIVACY CONTACT EMAIL]**. The deployment must establish and test an account/data deletion process before public launch, including its treatment of backups and logs.

## Changes

This notice must be reviewed and updated when processing, providers, retention periods or deployment regions change.
