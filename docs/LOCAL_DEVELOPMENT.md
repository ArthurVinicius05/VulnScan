# Local development setup — MFA and Website Scanner

These instructions are for a local developer environment only. Do not copy development settings into a public production deployment.

## Configure MFA encryption

The backend intentionally refuses MFA setup when `MFA_ENCRYPTION_KEY` is empty. This key is a server-side encryption secret, not a user password and not a value that should be placed in frontend code.

1. Start the normal local stack once:
   ```powershell
   docker compose up --build -d
   ```
2. Generate a Fernet key inside the backend container:
   ```powershell
   docker compose exec backend python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
3. Open the local `.env` file and set the generated value:
   ```dotenv
   MFA_ENCRYPTION_KEY=paste-the-generated-key-here
   ```
4. Recreate the backend so it reads the key:
   ```powershell
   docker compose up -d --force-recreate backend
   ```
5. Retry MFA setup in the application and follow the authenticator verification flow. Save the recovery codes securely.

**Important:** keep the same key across restarts and backups. Do not commit `.env`, publish the key, or generate a replacement after MFA secrets have been stored. Losing the key prevents decryption of existing MFA secrets.

## Run the isolated passive Website Scanner locally

The Website Scanner is a bounded passive HTTP check. It does not run exploit payloads, fuzzing, or active vulnerability exploitation. Use only websites you own or are explicitly authorized to assess.

1. In `.env`, set:
   ```dotenv
   ENABLE_WEBSITE_SCAN=true
   ```
2. Start the stack with the dedicated worker profile:
   ```powershell
   docker compose --profile website-scan up --build -d
   ```
3. Confirm the worker is healthy:
   ```powershell
   docker compose ps
   docker compose logs --tail=100 website-worker backend
   ```

The production Compose configuration intentionally keeps Website Scanner disabled. Do not enable it for a public deployment until the production egress and SSRF validation gates have passed.
