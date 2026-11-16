# VulnScan production operations runbook

This runbook describes the work that must happen on the actual hosting environment. Passing repository CI does not prove that DNS, firewall rules, TLS, SMTP, storage, monitoring or legal controls are correct.

## 1. Prepare the host and domain

- Use a supported Linux host with Docker Engine and the Docker Compose plugin.
- Point the production DNS A/AAAA records to the host before requesting a public certificate.
- Keep ports 8000, 8001, 5432, 6379 and 9090 private. The Compose profile publishes the frontend only on 127.0.0.1:8080 and Prometheus only on 127.0.0.1:9090.
- Do not expose the development Compose profile.

For a host-level Caddy installation, a minimal site block is:

~~~caddy
vulnscan.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080
}
~~~

Replace the example domain. Confirm certificate issuance and HTTPS redirects before enabling HSTS. Do not bind the frontend container directly to a public interface.

## 2. Create and store production secrets

Copy .env.production.example to .env.production and generate independent secrets:

~~~bash
openssl rand -hex 32
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
age-keygen
~~~

Use independent random values for POSTGRES_PASSWORD, SCANNER_WORKER_TOKEN and OPS_ADMIN_TOKEN. Use the Fernet output for MFA_ENCRYPTION_KEY and the age public recipient for BACKUP_RECIPIENT.

- Keep .env.production, the age private identity and the rclone configuration out of Git.
- Restrict the environment file to the deployment operator (chmod 600 .env.production).
- Store a protected copy of the age private identity separately from the host.
- The MFA encryption key is not an ordinary password: use the transactional rotation procedure below; never replace it directly while encrypted TOTP secrets exist.

### Rotate the MFA encryption key

1. Take and verify a fresh encrypted PostgreSQL backup.
2. Stop the API and analysis worker while leaving PostgreSQL running:

~~~bash
docker compose --env-file .env.production -f docker-compose.production.yml stop backend analysis-worker
~~~

3. Create a chmod-600 temporary file outside Git containing OLD_MFA_ENCRYPTION_KEY and NEW_MFA_ENCRYPTION_KEY. Load it into the shell without printing either value:

~~~bash
set -a
source ./mfa-rotation.env
set +a
~~~

4. Run a validation-only dry run, then apply the transaction:

~~~bash
docker compose --env-file .env.production -f docker-compose.production.yml run --rm --no-deps -e OLD_MFA_ENCRYPTION_KEY -e NEW_MFA_ENCRYPTION_KEY backend python -m app.rotate_mfa_key
docker compose --env-file .env.production -f docker-compose.production.yml run --rm --no-deps -e OLD_MFA_ENCRYPTION_KEY -e NEW_MFA_ENCRYPTION_KEY backend python -m app.rotate_mfa_key --apply
~~~

5. Only after the apply command succeeds, replace MFA_ENCRYPTION_KEY in .env.production with NEW_MFA_ENCRYPTION_KEY, remove the temporary file, unset both temporary variables and restart the services:

~~~bash
unset OLD_MFA_ENCRYPTION_KEY NEW_MFA_ENCRYPTION_KEY
rm -f ./mfa-rotation.env
docker compose --env-file .env.production -f docker-compose.production.yml up -d backend analysis-worker
~~~

6. Verify TOTP login for a test account. If the dry run or apply fails, the transaction is rolled back; keep the old key active and investigate before restarting.

Rotate SCANNER_WORKER_TOKEN by changing the same value for backend and scanner-worker and restarting both. Rotate OPS_ADMIN_TOKEN by changing the backend environment and restarting it. Do not log or paste secrets into tickets.
- Never put OPS_ADMIN_TOKEN in the frontend, browser storage, screenshots or support logs.

## 3. Validate and start the production profile

Before starting, confirm that DATABASE_URL uses the same database, user and URL-encoded password as the PostgreSQL environment variables. Set CORS_ORIGINS and FRONTEND_URL to the real HTTPS origin. Keep ENABLE_WEBSITE_SCAN and ENABLE_OSV_SCAN disabled.

~~~bash
docker compose --env-file .env.production -f docker-compose.production.yml config --quiet
docker compose --env-file .env.production -f docker-compose.production.yml up --build -d
docker compose --env-file .env.production -f docker-compose.production.yml ps
~~~

Verify /api/health, registration, email verification, login, MFA enrollment, password recovery and a small authorized source-code analysis. Use only test accounts and source code that is safe to upload.

## 4. Apply and test egress restrictions

The intended network policy is:

- PostgreSQL, Redis, API, frontend, analysis worker and scanner worker stay on internal Docker networks.
- Only smtp-proxy is attached to the egress network.
- smtp-proxy resolves one configured SMTP_UPSTREAM_HOST at startup, rejects non-public IP answers and permits only STARTTLS ports 25, 587 or 2525.
- Website scanning and online OSV scanning remain disabled.

Docker bridge traffic can bypass simple UFW rules. Apply the host firewall policy through the host's supported Docker forwarding path (DOCKER-USER chain or equivalent nftables forward chain), not by assuming UFW alone filters container egress.

Resolve SMTP_UPSTREAM_HOST and allow only the provider's current public destination IPs and the required TCP port from the SMTP proxy network. Allow only the DNS traffic required by the host/Docker resolver. Deny other outbound traffic from the proxy network. Revalidate the allowlist when the provider changes its IP ranges.

Acceptance checks:
- SMTP proxy can reach the configured relay and complete STARTTLS with the expected certificate hostname.
- Backend, analysis worker and scanner worker cannot make arbitrary external HTTP/HTTPS connections.
- The SMTP proxy cannot connect to arbitrary public IPs or unrelated ports.
- Website/OSV workers remain disabled and isolated.

Record the firewall rules, allowed relay IPs, DNS resolver and the date they were last verified. Do not enable website or OSV scanning until a separate SSRF, redirect, DNS-rebinding and egress review has passed.

## 5. Verify SMTP deliverability

Use a real sender domain and provider credentials. Configure the domain's SPF and DKIM records and publish a DMARC policy. Send confirmation and password-reset messages to test mailboxes at more than one provider; inspect delivery, spam placement, TLS and bounce handling. Confirm that MAIL_FROM is authorized by the SMTP provider.

## 6. Schedule encrypted backups and prove restore

Install age and rclone on the host. Configure rclone for the same Unix account that runs the systemd service (root by default). If using a dedicated account, grant it Docker access and update the service User= setting. Set BACKUP_REMOTE in .env.production and test a manual backup first:

~~~bash
bash scripts/backup_postgres.sh
~~~

The script writes an age-encrypted PostgreSQL dump and SHA-256 checksum locally, then uploads both files when BACKUP_REMOTE is configured. Configure object-storage lifecycle/retention separately; an upload is not a retention policy. After a successful remote upload, local encrypted files older than BACKUP_LOCAL_RETENTION_DAYS (14 by default) are pruned. Without a remote target, local backups are never automatically deleted.

The repository includes a daily systemd timer template. Adjust /opt/vulnscan in deploy/systemd/vulnscan-backup.service to the installation path before installing it:

~~~bash
sudo cp deploy/systemd/vulnscan-backup.service deploy/systemd/vulnscan-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vulnscan-backup.timer
systemctl list-timers vulnscan-backup.timer
~~~

Perform a restore drill in a separate staging database using scripts/restore_postgres.sh. Confirm row counts, account access, audit history, MFA recovery and application health before accepting the drill. Never test destructive restore commands against the only production database.

## 7. Monitoring, logs and incident response

- Prometheus scrapes API request, latency, queue and metrics-collection signals. Its UI is bound to loopback; access it through an SSH tunnel.
- Configure Alertmanager or an equivalent notification service before launch. The repository includes Prometheus alert rules but does not yet deliver external notifications.
- Configure centralized log shipping, access control, retention and redaction. Docker's local JSON log rotation is not a centralized log-management system.
- Assign an operator responsible for alerts, incident response, backup checks, restore drills and dependency updates.
- Document how to disable registration, stop workers, revoke sessions, rotate API/SMTP/operations credentials and preserve forensic logs after an incident.

## 8. Privacy, deletion and independent review

Before public registration:
- Replace placeholders in PRIVACY.md and TERMS.md with the real controller/operator name, contact, hosting region, subprocessors, transfer details, lawful basis and retention policy.
- Have the privacy notice and terms reviewed for LGPD by a qualified professional.
- Define how account deletion requests affect active data, off-site backups, infrastructure logs and backup expiry.
- Commission an independent security review or penetration test. Fix findings and rerun CI before launch.

## Launch decision

Do not accept untrusted public uploads until the host firewall, HTTPS, SMTP deliverability, off-site backup/restore, alert notifications, centralized logs, privacy documents and independent security review have all been verified. A green CI pipeline is necessary, not sufficient, for public launch.
