# Центральный API

Интерфейс `ICentralReporter` отделяет приложение от транспорта. `DisabledCentralReporter` используется по умолчанию. `HttpCentralReporter` отправляет heartbeat, результаты проверок, инциденты, сигналы и discovery report в `/api/v1/agent/*`, использует bearer-токен из `SCADAGUARD_API_TOKEN`, ограниченный timeout и локальную очередь при ошибке.

Discovery и конфигурация:

- `POST /api/v1/agent/discovery` — идемпотентный ingest отчёта;
- `GET /api/v1/agent/config` и `POST /api/v1/agent/config/status` — получение/результат применения desired configuration;
- `GET /api/v1/agents/{id}/discovery` — последний отчёт для авторизованного Web;
- `GET|PUT /api/v1/agents/{id}/configuration` — просмотр/изменение конфигурации;
- `POST /api/v1/agents/{id}/configuration/confirm-archive` — подтверждение read-only кандидата;
- `POST /api/v1/agents/{id}/discovery/rescan` — запрос нового сканирования при следующем исходящем опросе агента.

Изменения конфигурации версионируются, хешируются и пишутся в audit log. Server никогда не отправляет команды MasterSCADA. Для production разрешён только HTTPS.
