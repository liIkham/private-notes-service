# Private Notes Service

Сервис приватных заметок на FastAPI, SQLAlchemy 2.x и PostgreSQL. Реализованы
cookie-based JWT authentication, CSRF-защита, owner-scoped CRUD заметок,
read-only административный просмотр заметок, управление пользователями и
минимальный встроенный Jinja2/vanilla JavaScript frontend.

Архитектурные решения и границы текущего этапа описаны в
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## Стек

- Python 3.11+, FastAPI и Jinja2;
- SQLAlchemy 2.x, PostgreSQL и psycopg;
- Alembic;
- Pydantic Settings;
- Argon2 (`pwdlib`) и PyJWT;
- HTML, CSS и vanilla JavaScript без Node.js toolchain.

## Требования

Для рекомендуемого запуска нужны Docker Desktop либо Docker Engine с Docker
Compose v2. Порты `8000` и `5432` должны быть свободны либо переопределены в
`.env`. Для запуска без Docker нужны Python 3.11+ и доступный PostgreSQL; версия
PostgreSQL в Compose — 17.

## Запуск через Docker Compose

1. Скопируйте `.env.example` в `.env`:

   ```powershell
   Copy-Item .env.example .env
   ```

   Для Linux/macOS:

   ```bash
   cp .env.example .env
   ```

   Задайте в `.env` локальный пароль PostgreSQL и замените намеренно невалидный
   `JWT_SECRET_KEY=CHANGE_ME` случайной строкой длиной не менее 32 символов.
   С placeholder приложение завершится при старте. Случайное значение можно
   получить, например, командой `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
   Не добавляйте созданный `.env` в Git.
2. Соберите и запустите приложение:

   ```bash
   docker compose up -d --build
   ```

3. Примените миграции — автоматически при старте они не запускаются:

   ```bash
   docker compose exec api alembic upgrade head
   ```

4. Убедитесь, что PostgreSQL имеет статус `healthy`, а API отвечает:

   ```bash
   docker compose ps
   curl http://localhost:8000/health
   ```

5. Откройте `http://localhost:8000/` в браузере.

Основные страницы:

- `/login` — вход;
- `/register` — регистрация;
- `/notes` — личные заметки;
- `/admin` — панель администратора;
- `/health` — проверка состояния API.

Документация API:

- Swagger UI: `http://localhost:8000/docs`;
- OpenAPI JSON: `http://localhost:8000/openapi.json`.

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

```bash
python -m venv .venv
# Активируйте окружение подходящей для вашей ОС командой.
python -m pip install -e ".[dev]"
# Скопируйте .env.example в .env, проверьте DATABASE_URL и JWT_SECRET_KEY.
alembic upgrade head
uvicorn app.main:app --reload
```

Полный набор тестов запускается из корня проекта и использует изолированную
тестовую БД, а не данные из Docker volume:

```bash
python -m pytest
```
