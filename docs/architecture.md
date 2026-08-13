# Архитектура

`Application` связывает независимое ядро с адаптерами. `IHealthCheck` и `CheckScheduler` выполняют системные проверки; `DataQualityAnalyzer` работает только с `SignalSample`; `IncidentManager` преобразует результаты в устойчивый жизненный цикл инцидента. WinAPI сосредоточен в проверках и `WindowsServiceHost`.

`LocalStorage` пишет только в собственную SQLite-базу ScadaGuard. `SqliteArchiveDataSource` открывает внешний архив строго read-only. `AgentState` публикует атомарные снимки через loopback HTTP API. Все циклы получают `std::stop_token`; SCM и Ctrl+C только запрашивают остановку.

Граница безопасности: сбор данных → анализ → локальное состояние/события. Обратного управляющего пути к MasterSCADA нет.
