# Устранение проблем

## Agent не собирается

Запустите `scripts/bootstrap-windows.ps1` через `-ExecutionPolicy Bypass`. Скрипт перечислит отсутствующие VS C++ workload, CMake и `VCPKG_ROOT`, но ничего не установит без `-InstallMissing`.

## Конфигурация не загружена

Используйте `--validate-config`, затем `/api/v1/config/status`. Неизвестный источник остаётся `Unknown`; проверьте `unconfigured_subsystems` и warnings.

## Данные не доходят

Проверьте `SCADAGUARD_API_TOKEN`, central base URL, TLS trust, `/api/v1/queue/status` и Server logs. При восстановлении связи очередь отправляется с исходными `message_id` и sequence numbers.

## Web показывает ошибку API

Проверьте `docker compose ps`, healthchecks Server/PostgreSQL и `/healthz`. UI намеренно не показывает stale cache как актуальные данные после ошибки.
