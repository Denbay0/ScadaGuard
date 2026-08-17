# ScadaGuard production deployment

- Compose project: `scadaguard`
- Internal Web endpoint: `http://127.0.0.1:8320`
- Public endpoint: `https://scada.micom.su`
- PostgreSQL and FastAPI are reachable only inside `scadaguard-internal`.
- Runtime secrets are stored only in `/opt/scadaguard/.env` with mode `0600`.
- Initial credentials and the one-time Agent token are placed in `/opt/scadaguard/secrets` with root-only permissions for secure handoff.
- Daily PostgreSQL dumps are retained under `/opt/scadaguard/backups` for 14 days.

Use `/opt/scadaguard/backup-postgres.sh` before updates. See `docs/production-update.md` for update and recovery procedures.
