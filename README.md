# ScadaGuard

ScadaGuard — система read-only мониторинга компьютеров MasterSCADA: Windows-агент на C++20, центральный FastAPI/PostgreSQL-сервер и русскоязычная React-панель.

Агент проверяет процессы, службы, TCP-порты, диски, активность файлов и логи, анализирует качество технологических данных, хранит состояние локально и отправляет сообщения на сервер только исходящими HTTPS-запросами. Сервер дедуплицирует сообщения, хранит историю, обнаруживает потерю связи и предоставляет защищённый web API.

## Состояние разработки

Работают базовые контуры Agent → HTTP API → PostgreSQL → Web, авторизация пользователей, регистрация объектов/агентов, одноразовые agent tokens, локальная очередь, offline/recovery detection, retention и Docker deployment. Реальное OPC UA-подключение, подтверждённая схема архива MasterSCADA, Mattermost и графики сигналов ещё не завершены; эти подсистемы не выдают фиктивный `OK`.

## Быстрый запуск сервера

Нужны Docker Engine и Docker Compose.

```powershell
Copy-Item .\deploy\.env.example .\deploy\.env
# Замените два placeholder-секрета в deploy\.env.
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml up -d --build
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml exec server python -m app.cli create-admin
```

Панель откроется на `http://localhost:8080`. Миграции Alembic выполняются перед каждым стартом backend. Vite dev server в production не используется: статический build отдаёт Caddy.

Для локального Windows Agent используйте loopback-only override и development bootstrap:

```powershell
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml -f .\deploy\docker-compose.dev.yml up -d --build
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml -f .\deploy\docker-compose.dev.yml exec server python -m app.cli bootstrap-demo --host-id local-windows
# Скопируйте выданный один раз токен только в окружение текущего процесса.
$env:SCADAGUARD_API_TOKEN = '<token>'
.\build\windows-msvc\RelWithDebInfo\scadaguard.exe --console --config .\config\config.local-masterscada.json
```

Автоматический локальный smoke/E2E, включая `agent_offline` и recovery:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-local-e2e.ps1 -TestOfflineRecovery
```

Скрипт использует случайные временные credentials, удаляет тестового администратора и не сохраняет raw token.

Практическая регистрация первого объекта и агента описана в [docs/first-site-setup.md](docs/first-site-setup.md).

## Сборка Windows Agent

Требуются Windows x64, Visual Studio 2022 с workload Desktop development with C++, CMake 3.25+ и vcpkg. Скрипт проверки ничего не устанавливает без явного `-InstallMissing`.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap-windows.ps1
$env:VCPKG_ROOT = 'C:\Tools\vcpkg'
powershell -ExecutionPolicy Bypass -File .\scripts\build-agent.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\test-agent.ps1
```

После сборки:

```powershell
.\build\windows-msvc\RelWithDebInfo\scadaguard.exe --version
.\build\windows-msvc\RelWithDebInfo\scadaguard.exe --validate-config --config .\config\config.example.json
.\build\windows-msvc\RelWithDebInfo\scadaguard.exe --console --config C:\ProgramData\ScadaGuard\config.json
```

Локальный API слушает только `127.0.0.1:9180`: `/api/v1/health`, `/checks`, `/incidents`, `/signals`, `/config/status`, `/queue/status`, `/version`, `/discovery`, `/discovery/rescan` и `/metrics`.

Безопасное autodiscovery можно также запустить отдельно: `--discover`, `--discover --json`, `--discover-masterscada`, `--discover-archives` или `--discover-logs`. Эти команды только читают локальные метаданные и завершаются сообщением, что MasterSCADA не изменялась.

## Проверки

```powershell
# Server
cd server
.\.venv\Scripts\python.exe -m ruff format --check app tests
.\.venv\Scripts\python.exe -m ruff check app tests
.\.venv\Scripts\python.exe -m mypy app
.\.venv\Scripts\python.exe -m pytest

# Web
cd ..\web
pnpm lint
pnpm test
pnpm build
```

Windows CI собирает Agent через MSVC/vcpkg и запускает CTest. Отдельный CI использует PostgreSQL service container, применяет Alembic, проверяет Server/Web и собирает Docker images.

## Безопасность

ScadaGuard не управляет MasterSCADA и не пишет в её проект или архив. SQLite-архив открывается read-only. Токены читаются из окружения, на сервере сохраняются только SHA-256 hashes, а выданный raw token показывается один раз. Реальные секреты, пароли и сертификаты в репозиторий не входят.

Документация: [архитектура](docs/system-architecture.md), [установка агента](docs/agent-installation.md), [deployment сервера](docs/server-deployment.md), [протокол](docs/api-protocol.md), [безопасность](docs/security.md), [устранение проблем](docs/troubleshooting.md).
