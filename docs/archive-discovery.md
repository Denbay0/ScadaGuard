# Исследование архива MasterSCADA

Исследование проводится только read-only на копии либо с отдельными правами чтения. Зафиксируйте расположение файлов, формат SQLite, таблицы, тип timestamps, идентификатор сигнала, value/quality columns и правила ротации.

Внешний SQLite Agent открывает с `SQLITE_OPEN_READONLY`; table/column identifiers проходят whitelist. Пока mapping не подтверждён, archive source должен оставаться disabled и отражаться как unconfigured/Unknown. Никакие migrations или repair-команды к промышленному архиву не применяются.
