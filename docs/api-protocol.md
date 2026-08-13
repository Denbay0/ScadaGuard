# Agent protocol v1

Пять ingest endpoint принимают один envelope:

```json
{
  "message_id": "uuid-v4",
  "protocol_version": 1,
  "message_kind": "heartbeat",
  "agent_id": "stable-agent-id",
  "site_id": "stable-site-id",
  "host_id": "stable-host-id",
  "boot_id": "uuid-v4",
  "sequence_number": 1,
  "created_at": "2026-08-05T12:00:00Z",
  "payload": {}
}
```

Endpoints: `/api/v1/agent/heartbeat`, `/check-results/batch`, `/incidents/batch`, `/signal-samples/batch`, `/discovery`. Заголовок — `Authorization: Bearer <agent-token>`. `message_kind` обязан соответствовать endpoint. Повтор того же UUID возвращает `duplicate: true` и не создаёт повторных записей. Sequence number сохраняется для диагностики пропусков; message identity задаёт UUID.

Check/incident/sample batches передают элементы в `payload.items`. Timestamps должны содержать timezone. Сервер отклоняет несовпадающие `agent_id`/`host_id` и revoked token.
