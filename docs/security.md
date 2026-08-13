# Модель безопасности

- Agent устанавливает только исходящие соединения; локальный API привязан к loopback.
- Production central URL обязан использовать HTTPS.
- Agent token передаётся через `SCADAGUARD_API_TOKEN`; Server хранит SHA-256 hash и поддерживает отзыв.
- Пользовательские пароли хэшируются Argon2, сессия подписывается HMAC и хранится в HttpOnly/SameSite cookie.
- Операции создания объектов/агентов, token lifecycle и acknowledgment пишутся в audit log.
- MasterSCADA, её проект и архив никогда не изменяются.

Секреты задаются только через environment/secret manager. Не публикуйте `.env`, state database, логи с чувствительными полями или реальные сертификаты.
