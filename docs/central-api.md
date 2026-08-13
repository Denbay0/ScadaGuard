# Центральный API

Центральный сервер не является частью MVP. Интерфейс `ICentralReporter` отделяет приложение от транспорта. `DisabledCentralReporter` используется по умолчанию. `HttpCentralReporter` отправляет JSON heartbeat в `POST /api/v1/heartbeats` и события в `POST /api/v1/events`, использует bearer-токен из `SCADAGUARD_API_TOKEN`, ограниченный timeout и локальную очередь при ошибке.

Для production разрешён только HTTPS. Перед включением нужно согласовать контракт JSON, доверенную цепочку сертификатов, правила retry/idempotency и политику хранения событий.
