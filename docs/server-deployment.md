# Развёртывание Server и Web

Скопируйте `deploy/.env.example` в `deploy/.env`, замените оба placeholder-секрета и выполните:

```powershell
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml up -d --build
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml ps
```

PostgreSQL использует named volume. Backend ждёт healthy database, выполняет `alembic upgrade head`, затем запускает Uvicorn. Web — production React build в Caddy на порту 8080.

Для внешнего `https://scada.micom.su` используйте `deploy/Caddyfile.example` в отдельно управляемом reverse proxy. Сертификаты не запрашиваются и не выпускаются репозиторием автоматически. При HTTPS задайте `SCADAGUARD_PUBLIC_URL=https://scada.micom.su` и `SCADAGUARD_COOKIE_SECURE=true`.
