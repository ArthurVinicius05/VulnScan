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
BACKUP_REMOTE="$(read_env_value BACKUP_REMOTE)"
BACKUP_LOCAL_RETENTION_DAYS="$(read_env_value BACKUP_LOCAL_RETENTION_DAYS)"
BACKUP_LOCAL_RETENTION_DAYS="${BACKUP_LOCAL_RETENTION_DAYS:-14}"
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
if [[ -n "$BACKUP_REMOTE" ]]; then
  command -v rclone >/dev/null || { echo "BACKUP_REMOTE is set but rclone is not installed." >&2; exit 1; }
  REMOTE_DIR="${BACKUP_REMOTE%/}"
  rclone copyto "$BACKUP_FILE" "$REMOTE_DIR/$(basename "$BACKUP_FILE")"
  rclone copyto "$BACKUP_FILE.sha256" "$REMOTE_DIR/$(basename "$BACKUP_FILE").sha256"
  echo "Encrypted backup and checksum uploaded to $REMOTE_DIR"
  [[ "$BACKUP_LOCAL_RETENTION_DAYS" =~ ^[1-9][0-9]*$ ]] || { echo "BACKUP_LOCAL_RETENTION_DAYS must be a positive integer." >&2; exit 1; }
  find "$BACKUP_DIR" -maxdepth 1 -type f \\
    \\( -name "vulnscan-postgres-*.dump.age" -o -name "vulnscan-postgres-*.dump.age.sha256" \\) \\
    -mtime +"$BACKUP_LOCAL_RETENTION_DAYS" -delete
fi
echo "Encrypted PostgreSQL backup created: $BACKUP_FILE"
