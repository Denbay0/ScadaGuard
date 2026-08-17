# Развёртывание Server и Web

Production-процедуры обновления, rollback, backup и восстановления описаны в [production-update.md](production-update.md).

Скопируйте `deploy/.env.example` в `deploy/.env`, замените оба placeholder-секрета и выполните:

```powershell
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml up -d --build
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml ps
```

PostgreSQL использует named volume. Backend ждёт healthy database, выполняет `alembic upgrade head`, затем запускает Uvicorn. Web — production React build в Caddy на порту 8080.

В production-базе Compose PostgreSQL и FastAPI не публикуются наружу. Для разработки добавьте `docker-compose.dev.yml`: он публикует PostgreSQL на `127.0.0.1:55432` и FastAPI на `127.0.0.1:8000`; Web остаётся на `http://localhost:8080`. Кодовые базы dev/prod одинаковы, различаются только environment и Compose override.

Development CLI:

```powershell
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml exec server python -m app.cli create-admin
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml exec server python -m app.cli create-site --slug site --name "Объект"
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml exec server python -m app.cli create-agent --agent-id agent --site-slug site --host-id host --name "Агент" --heartbeat-interval-seconds 30
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml exec server python -m app.cli create-agent-token --agent-id agent
```

`bootstrap-demo` разрешён только при loopback `SCADAGUARD_PUBLIC_URL`. Пароль non-interactive пользователя приходит через `SCADAGUARD_BOOTSTRAP_PASSWORD`; Agent token печатается один раз и дальше передаётся Windows Agent через `SCADAGUARD_API_TOKEN`.

Для внешнего `https://scada.micom.su` используйте `deploy/Caddyfile.example` в отдельно управляемом reverse proxy. Сертификаты не запрашиваются и не выпускаются репозиторием автоматически. При HTTPS задайте `SCADAGUARD_PUBLIC_URL=https://scada.micom.su` и `SCADAGUARD_COOKIE_SECURE=true`.
