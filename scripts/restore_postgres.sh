#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
if [[ "${CONFIRM_RESTORE:-}" != "YES" ]]; then
  echo "Restore replaces database objects. Stop backend and analysis-worker first, then set CONFIRM_RESTORE=YES." >&2
  exit 1
fi
ENV_FILE="${ENV_FILE:-.env.production}"
: "${BACKUP_FILE:?Set BACKUP_FILE to the encrypted .age backup path}"
: "${BACKUP_IDENTITY:?Set BACKUP_IDENTITY to the private age identity file}"
[[ -f "$ENV_FILE" && -f "$BACKUP_FILE" && -f "$BACKUP_IDENTITY" ]] || {
  echo "Environment file, backup or age identity not found." >&2
  exit 1
}
read_env_value() {
  local key="$1" value="${!1:-}"
  if [[ -z "$value" ]]; then
    value="$(grep -m1 -E "^$key=" "$ENV_FILE" | cut -d= -f2- || true)"
    value="${value%\"}"; value="${value#\"}"
    value="${value%\'}"; value="${value#\'}"
  fi
  printf '%s' "$value"
}
POSTGRES_USER="$(read_env_value POSTGRES_USER)"
POSTGRES_DB="$(read_env_value POSTGRES_DB)"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
command -v age >/dev/null || { echo "Install age before restoring encrypted backups." >&2; exit 1; }
[[ -f "$BACKUP_FILE.sha256" ]] || { echo "Backup checksum file is missing." >&2; exit 1; }
(cd "$(dirname "$BACKUP_FILE")" && sha256sum --check "$(basename "$BACKUP_FILE").sha256")

age -d -i "$BACKUP_IDENTITY" "$BACKUP_FILE" \
  | docker compose --env-file "$ENV_FILE" -f docker-compose.production.yml exec -T db \
      pg_restore --exit-on-error --clean --if-exists --no-owner --no-acl \
        -U "$POSTGRES_USER" -d "$POSTGRES_DB"
echo "Restore completed. Verify the application and data before restarting services."
