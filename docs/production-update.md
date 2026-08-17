# Production update and recovery

The production deployment lives in `/opt/scadaguard`. Run all commands from that directory and operate only on the `scadaguard` Compose project.

## Update

1. Run `/opt/scadaguard/backup-postgres.sh` and verify that the new `.dump` file is non-empty.
2. Save the current source bundle or image identifiers under `/opt/scadaguard/releases`.
3. Copy the new `server`, `web`, `compose.yml`, and deployment scripts without replacing `.env`, `backups`, or Docker volumes.
4. Validate with `docker compose --env-file .env -f compose.yml config --quiet`.
5. Build with `docker compose --env-file .env -f compose.yml build`.
6. Apply migrations with `docker compose --env-file .env -f compose.yml run --rm server alembic upgrade head`.
7. Start with `docker compose --env-file .env -f compose.yml up -d`.
8. Verify `docker compose ps`, `GET /health`, login, and the Web dashboard.

Never run `down -v` during an update. The `scadaguard-postgres-data` volume is not deleted or recreated.

## Application rollback

Restore the preceding source bundle or image tags, rebuild only ScadaGuard, and run `docker compose up -d`. Do not downgrade the database until the migration compatibility of the older application has been verified. Check the current database revision with `docker compose exec -T server alembic current`.

## PostgreSQL recovery

Recovery is intentionally manual and destructive; do not perform it while the production database is healthy.

1. Stop only `scadaguard-server` and `scadaguard-web`.
2. Verify the selected dump with `pg_restore --list` in a temporary PostgreSQL environment.
3. Create a fresh temporary database and restore with `pg_restore --clean --if-exists --no-owner --no-acl`.
4. Verify row counts, the Alembic revision, admin login, site and agent registration.
5. Switch ScadaGuard to the verified restored database during an approved maintenance window.

Never restore or back up a MasterSCADA SQLite archive from the central server.

## Diagnostics

- Containers: `docker compose --env-file .env -f compose.yml ps`
- Logs: `docker compose --env-file .env -f compose.yml logs --tail=200 server web postgres`
- Migration: `docker compose --env-file .env -f compose.yml exec -T server alembic current`
- Internal health: `curl -fsS http://127.0.0.1:8320/health`
- Backup timer: `systemctl status scadaguard-backup.timer`
