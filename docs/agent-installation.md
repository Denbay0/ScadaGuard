# Установка Windows Agent

1. Соберите и протестируйте Agent командами из корневого README либо скачайте ZIP из Windows CI.
2. Создайте `C:\ProgramData\ScadaGuard\config.json` на основе `config\config.example.json`.
3. Замените все `configure-*` реальными именами процессов, служб, путями и signal IDs.
4. Установите выданный сервером token в защищённое окружение службы как `SCADAGUARD_API_TOKEN`; не помещайте его в JSON.
5. Выполните `scadaguard.exe --validate-config --config C:\ProgramData\ScadaGuard\config.json`.
6. Проверьте `--once`, локальные `/api/v1/health` и `/api/v1/config/status`.
7. Из повышенной PowerShell выполните `scadaguard.exe --install --config C:\ProgramData\ScadaGuard\config.json`.

Удаление выполняется только явной командой `scadaguard.exe --uninstall`. Логи и state database сохраняются в `%ProgramData%\ScadaGuard`.
