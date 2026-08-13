# Настройка первого объекта

1. Разверните compose и создайте администратора: `docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml exec server python -m app.cli create-admin`.
2. Откройте `http://localhost:8080` и войдите.
3. Через OpenAPI (`http://localhost:8080/docs`) выполните `POST /api/v1/sites`.
4. Выполните `POST /api/v1/agents`, указав UUID объекта, стабильные `agent_id` и `host_id`.
5. Выполните `POST /api/v1/agents/{agent_uuid}/tokens`. Скопируйте token сразу: повторно он не показывается.
6. Установите Agent, передайте token только через `SCADAGUARD_API_TOKEN`, настройте совпадающие agent/site/host identifiers.
7. Проверьте локальные configuration status и queue status, затем первый heartbeat на dashboard.
8. Настройте реальные process/service checks и OPC UA только после проверки endpoint/node IDs.
9. Выполните read-only inspection архива и внесите mapping.
10. Безопасно остановите тестовый check, убедитесь в открытии incident, затем восстановите его и проверьте recovery.

Административный UI пока не завершён, поэтому шаги 3–5 выполняются через сессионно защищённый OpenAPI/API.
