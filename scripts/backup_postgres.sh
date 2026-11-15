#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
ENV_FILE="${ENV_FILE:-.env.production}"
[[ -f "$ENV_FILE" ]] || { echo "Missing $ENV_FILE; configure it first." >&2; exit 1; }

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
BACKUP_RECIPIENT="$(read_env_value BACKUP_RECIPIENT)"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${BACKUP_RECIPIENT:?Set BACKUP_RECIPIENT to an age public recipient}"
command -v age >/dev/null || { echo "Install age before creating encrypted backups." >&2; exit 1; }

BACKUP_DIR="${BACKUP_DIR:-$ROOT_DIR/backups}"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_FILE="$BACKUP_DIR/vulnscan-postgres-$STAMP.dump.age"
TEMP_FILE="$BACKUP_FILE.partial"
umask 077
trap 'rm -f "$TEMP_FILE"' EXIT

docker compose --env-file "$ENV_FILE" -f docker-compose.production.yml exec -T db \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc \
  | age -r "$BACKUP_RECIPIENT" -o "$TEMP_FILE"
mv "$TEMP_FILE" "$BACKUP_FILE"
(cd "$BACKUP_DIR" && sha256sum "$(basename "$BACKUP_FILE")" > "$(basename "$BACKUP_FILE").sha256")
chmod 600 "$BACKUP_FILE" "$BACKUP_FILE.sha256"
echo "Encrypted PostgreSQL backup created: $BACKUP_FILE"
