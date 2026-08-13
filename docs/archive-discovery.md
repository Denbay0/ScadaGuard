# Исследование архива MasterSCADA

Исследование проводится только read-only на копии либо с отдельными правами чтения. Зафиксируйте расположение файлов, формат SQLite, таблицы, тип timestamps, идентификатор сигнала, value/quality columns и правила ротации.

Внешний SQLite Agent открывает с `SQLITE_OPEN_READONLY`; table/column identifiers проходят whitelist. Пока mapping не подтверждён, archive source должен оставаться disabled и отражаться как unconfigured/Unknown. Никакие migrations или repair-команды к промышленному архиву не применяются.

`MasterScadaDiscovery` сначала собирает ограниченные roots из процессов, Windows Services, uninstall registry и конфигурируемых hints. Затем выполняется bounded scan с лимитами каталогов, файлов, глубины, времени и размера читаемых фрагментов. Корень диска, сетевые пути, `C:\Windows`, `C:\Users` и reparse points не обходятся. SQLite определяется по 16-байтному magic header, а не по расширению, и открывается только `SQLITE_OPEN_READONLY`.

Инспектор читает только метаданные: таблицы/views, типы колонок, индексы, foreign keys, bounded row count (не более 10 000), до пяти sample rows и не более 64 KiB sample data. На один файл действует двухсекундный progress-handler deadline. `ArchiveSchemaAnalyzer` отдельно оценивает timestamp/signal-id/value/quality по именам, SQLite types, индексам, связям и реальным ограниченным samples. Он не содержит названий таблиц MasterSCADA и при неоднозначности выставляет `needs_confirmation`. MIN/MAX timestamp читаются только через найденный поддерживающий индекс.

Web-раздел «Архив → Инспектор» доступен администратору. Подтверждение пути и mapping создаёт versioned desired configuration; Agent повторно проверяет локальный путь и whitelist идентификаторов перед включением SQLite source. Чтение telemetry ограничено 5 000 строками, 1 MiB и двухсекундным deadline; полный технологический архив на Server не копируется.

Статусы `detected`, `confirmed`, `configured`, `monitoring`, `not_found`, `ambiguous`, `unsupported` и `error` намеренно различаются. Наличие SQLite рядом с MasterSCADA не подтверждает технологический архив. При нескольких сильных кандидатах требуется выбор администратора; исчезнувший подтверждённый файл не заменяется автоматически.
