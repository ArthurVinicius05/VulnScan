#!/usr/bin/env bash
set -Eeuo pipefail
: "${PGHOST:=localhost}"
: "${PGPORT:=5432}"
: "${PGUSER:=vulnscan}"
: "${PGPASSWORD:?PGPASSWORD is required}"
: "${PGDATABASE:=vulnscan_test}"
: "${PG_CLIENT_IMAGE:=postgres:16-alpine}"
command -v age >/dev/null
command -v age-keygen >/dev/null
command -v docker >/dev/null

pgclient() {
  docker run --rm --network host -i \
    -e PGHOST -e PGPORT -e PGUSER -e PGPASSWORD -e PGDATABASE \
    "$PG_CLIENT_IMAGE" "$@"
}

KEY_FILE="$(mktemp)"
DUMP_FILE="$(mktemp)"
rm -f "$KEY_FILE" "$DUMP_FILE"
RESTORE_DB="vulnscan_restore_${RANDOM}"
cleanup() {
  pgclient dropdb --if-exists "$RESTORE_DB" >/dev/null 2>&1 || true
  rm -f "$KEY_FILE" "$DUMP_FILE"
}
trap cleanup EXIT

age-keygen -o "$KEY_FILE" 2>/dev/null
RECIPIENT="$(age-keygen -y "$KEY_FILE")"
pgclient psql -v ON_ERROR_STOP=1 -d "$PGDATABASE" -c "CREATE TABLE IF NOT EXISTS backup_restore_probe (id integer primary key, value text not null); TRUNCATE backup_restore_probe; INSERT INTO backup_restore_probe VALUES (1, 'restore-ok');" >/dev/null
pgclient pg_dump -Fc "$PGDATABASE" | age -r "$RECIPIENT" -o "$DUMP_FILE"
pgclient createdb "$RESTORE_DB"
age -d -i "$KEY_FILE" "$DUMP_FILE" | pgclient pg_restore --exit-on-error --no-owner --no-acl -d "$RESTORE_DB"
VALUE="$(pgclient psql -At -d "$RESTORE_DB" -c "SELECT value FROM backup_restore_probe WHERE id=1")"
[[ "$VALUE" == "restore-ok" ]]
