# Архитектура ScadaGuard

Система состоит из Windows Agent, центрального Server и Web UI. Agent выполняет checks и read-only чтение источников, сохраняет состояние/очередь в собственной SQLite и отправляет protocol v1 envelopes исходящими запросами. Server проверяет bearer token, атомарно дедуплицирует `message_id`, записывает PostgreSQL и обслуживает UI. Web обращается к Server через same-origin Caddy reverse proxy.

Потерю компьютера определяет только Server: каждые 15 секунд он сравнивает `last_seen_at` с `max(default_offline_threshold, heartbeat_interval * 3)`, создаёт один `agent_offline` incident и закрывает его после восстановления.

Agent не открывает производственный порт: его диагностический API ограничен `127.0.0.1`. Центральный Server должен располагаться в офисном сегменте и приниматься через TLS reverse proxy.
