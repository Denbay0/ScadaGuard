#!/bin/sh
set -eu

deployment_directory="${SCADAGUARD_DEPLOYMENT_DIRECTORY:-/opt/scadaguard}"
backup_directory="$deployment_directory/backups"
compose_file="$deployment_directory/compose.yml"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
final_path="$backup_directory/scadaguard-$timestamp.dump"
temporary_path="$final_path.partial"

test -f "$compose_file"
install -d -m 0700 "$backup_directory"
trap 'rm -f "$temporary_path"' EXIT HUP INT TERM

docker compose --project-directory "$deployment_directory" --env-file "$deployment_directory/.env" \
  -f "$compose_file" exec -T postgres \
  pg_dump --format=custom --no-owner --no-acl --username=scadaguard --dbname=scadaguard \
  >"$temporary_path"

test -s "$temporary_path"
mv "$temporary_path" "$final_path"
chmod 0600 "$final_path"
find "$backup_directory" -maxdepth 1 -type f -name 'scadaguard-*.dump' -mtime +13 -delete
printf 'Created %s (%s bytes)\n' "$final_path" "$(wc -c <"$final_path")"
