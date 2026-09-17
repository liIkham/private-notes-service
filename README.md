# Private Notes Service

Сервис приватных заметок на FastAPI, SQLAlchemy 2.x и PostgreSQL. Реализованы
cookie-based JWT authentication, CSRF-защита, owner-scoped CRUD заметок,
read-only административный просмотр заметок, управление пользователями и
минимальный встроенный Jinja2/vanilla JavaScript frontend.

Архитектурные решения и границы текущего этапа описаны в
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## Запуск через Docker Compose

1. Скопируйте `.env.example` в `.env`, задайте локальный пароль PostgreSQL и
   замените намеренно невалидный `JWT_SECRET_KEY=CHANGE_ME` случайной строкой
   длиной не менее 32 символов. С placeholder приложение завершится при старте.
2. Соберите и запустите приложение:

   ```bash
   docker compose up -d --build
   ```

3. Примените миграции — автоматически при старте они не запускаются:

   ```bash
   docker compose exec api alembic upgrade head
   ```

4. Откройте `http://localhost:8000/` в браузере.

Основные страницы:

- `/login` — вход;
- `/register` — регистрация;
- `/notes` — личные заметки;
- `/admin` — панель администратора;
- `/health` — проверка состояния API.

Compose ожидает готовности PostgreSQL перед запуском API.

## Создание первого администратора

Публичная регистрация всегда создаёт обычного пользователя. После запуска
Compose и применения миграций первый администратор создаётся явной командой:

```bash
docker compose exec api python -m app.scripts.create_admin
```

Введите username, пароль и повтор пароля в интерактивных приглашениях. Пароль
не отображается в терминале. После успешного создания войдите через `/login` и
откройте `/admin`. Готовые учётные данные проект не содержит.

## Локальный запуск

Требуются Python 3.11+ и доступный PostgreSQL.

```bash
python -m venv .venv
# Активируйте окружение подходящей для вашей ОС командой.
python -m pip install -e ".[dev]"
# Скопируйте .env.example в .env, проверьте DATABASE_URL и JWT_SECRET_KEY.
uvicorn app.main:app --reload
```

Тесты запускаются командой:

```bash
pytest
```

Alembic связан с `Base.metadata`. Применить существующие миграции при локальном
запуске можно командой:

```bash
alembic upgrade head
```
