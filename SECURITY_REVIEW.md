# Независимый security review — 2026-09-17

Это снимок findings до final hardening pass. Источник выводов — код, тесты,
реальные HTTP-запросы, Chromium и PostgreSQL. Подтверждённые H1–H2, M1–M4 и
L1–L2 исправлены 2026-09-17; их `xfail`-сценарии стали обычными regression tests.
Разделы ниже сохраняют исходные сценарии и доказательства. CRITICAL без
дополнительных условий не подтверждён.

Текущее состояние после hardening и pre-submission pass: `203 passed`, failures
и `xfail` отсутствуют. Одноразовые live/browser/config probes удалены перед
сдачей; обычные regression tests сохранены. Поэтому сценарии, числа и приоритеты
ниже следует читать как исторический отчёт до исправлений, а не список открытых
дефектов текущей версии.

## Результаты проверок

| Проверка | Результат |
| --- | --- |
| Основной baseline без уже существующего `tests/security_review/` | 105 passed, 2 warnings, 0 failures |
| Полный набор, имевшийся на входе | 177 passed, 8 xfailed, 2 warnings |
| Полный набор после трёх дополнительных regression cases | 179 passed, 9 xfailed, 2 warnings |
| Девять известных дефектов с `--runxfail` | 9 failed, 74 deselected — дефекты действительно воспроизводятся |
| Compose config / build / старт с пустым volume | Успешно |
| Alembic upgrade с нуля | Обе ревизии применены |
| Alembic check после live-проверок | No new upgrade operations detected |
| Python compileall и импорты приложения/тестов | Ошибок не обнаружено |
| Chromium | Registration, login, CRUD, admin management, read-only admin notes, успешный logout работают |

Warnings: устаревающая интеграция Starlette TestClient с httpx и alias
`anyio.abc.BlockingPortal`. `xfail(strict=True)` документирует ожидаемо нарушенный
security contract; это не исправление и не успешно пройденная проверка безопасности.
Существующие тесты не удалены и не ослаблены.

На входе уже существовали audit-файлы и старый audit Docker project. Они сохранены.
Новые live-проверки выполнялись в `notes-review-final-917` с отдельным пустым
`notes-review-final-917_postgres_data`, API-портом 18027 и PostgreSQL-портом 15447.
Администратор создан через реальную интерактивную management command с getpass.
Пользовательские данные других проектов не изменялись.
После проверок созданные в этом проходе контейнеры, сеть и тестовый volume удалены;
эти временные пользователи и заметки не сохранены. Прежние audit-контейнеры оставлены.

## HIGH

### H1. Публичный JWT placeholder позволяет подписать admin token

- Код: `app/config.py:11`, `.env.example:13`, `docker-compose.yml:25`.
- Условие: оператор копирует пример без замены ключа. Проверяется только длина,
  а публичный placeholder длиннее 32 символов. Compose проверяет наличие значения.
- Воспроизведение: отдельный экземпляр приложения запущен с этим ключом;
  токен HS256 с `sub="1"` и будущим `exp`, подписанный публичной строкой, дал
  `200` на `/api/auth/me` и `/api/admin/users`, пользователь имел роль admin.
- Почему проблема: полная имперсонация существующих пользователей, включая admin.
  Это не обход подписи при сильном неизвестном ключе: проблема в принятии известного ключа.
  Текущий локальный `.env` содержит другой 64-символьный ключ.
- Тест: `test_example_secret_must_be_rejected`; дополнительно использовался
  одноразовый isolated live probe, не включённый в финальную сдачу.
- Минимальное исправление: пример, не проходящий validation, явный отказ для
  известных placeholders, обязательная генерация случайного deployment-secret.
  Уже развёрнутые экземпляры с публичным ключом требуют ротации.

### H2. Login/register отправляют пароль в URL при отказе JavaScript

- Код: `app/templates/login.html:10`, `app/templates/register.html:10`.
- Сценарий: JavaScript отключён, не загрузился или не успел установить submit handler.
  У формы отсутствует `method`; стандартное поведение браузера — GET.
- Воспроизведение: настоящий Chromium с отключённым JS отправил
  `/login?username=...&password=...` и аналогичный `/register`, включая repeat password.
  Контрольная строка пароля найдена в Uvicorn access-log.
- Почему проблема: пароль попадает в URL, историю и журналы запросов; потенциально
  может распространяться дальше через обработку URL/Referer.
- Тест: `test_password_form_has_no_native_get_fallback` для двух страниц;
  browser probe подтверждает реальную отправку, а не только отсутствие HTML-атрибута.
- Минимальное исправление: безопасный native POST fallback, который не выполняет
  операцию без обычных API/CSRF проверок, либо submit, недоступный до готовности JS;
  не допускать пароль в query string. Логи, уже содержащие пароли, считать чувствительными.

## MEDIUM

### M1. Приватный текст заметки попадает в серверный traceback

- Код: `app/database.py:11`, `app/services/notes.py:14`, `app/schemas/note.py:13`.
- Сценарий: авторизованный пользователь отправляет допустимую для Pydantic строку
  content с `\u0000`. PostgreSQL text не поддерживает NUL, INSERT завершается ошибкой.
- Воспроизведение: API вернул обычный `500 Internal Server Error` без текста заметки,
  но Docker log содержал `[parameters: ... 'content': 'PRIVATE_AUDIT_NOTE_SENTINEL_20260917\\x00' ...]`.
  SQLAlchemy engine использует `hide_parameters=False` по умолчанию.
- Почему проблема: персональные данные копируются в журналы с отдельными сроками
  хранения и правами доступа. Это утечка в лог, не доказанная выдача чужой заметки по HTTP.
- Тесты: `test_database_engine_hides_sensitive_parameters` и новый
  `test_failed_write_does_not_expose_private_note_in_exception`; live PostgreSQL/log check.
- Минимальное исправление: скрыть bound parameters, отклонять неподдерживаемый NUL,
  проверить sanitization сообщений драйвера/журналов. Одно `hide_parameters=True`
  не гарантирует очистку всех возможных PostgreSQL DETAIL-сообщений.

### M2. UI изображает успешный logout при сохранённой сессии

- Код: `app/static/js/api.js:133`, особенно `catch` на строке 140;
  кэш CSRF — `app/static/js/api.js:39`.
- Сценарий: вкладка A запомнила CSRF A; вкладка B получила B и заменила общую cookie.
  Logout из A получает 403. То же происходит при сетевом отказе.
- Воспроизведение в Chromium: в обоих случаях происходит redirect `/login`, но
  `/api/auth/me` возвращает 200 и открытие `/notes` не требует повторного входа.
  Успешный backend logout отдельно проверен: после него `/me` возвращает 401.
- Почему проблема: пользователь, особенно на общем устройстве, считает сессию закрытой.
  Rotation также нарушает mutations в старой вкладке до обновления CSRF.
- Тест: browser probe в изолированной среде; backend rotation покрыта
  сохраняемой в проекте CSRF-матрицей.
- Минимальное исправление: redirect только после подтверждённого logout; при ошибке
  показать её и разрешить повтор. Обновлять stale CSRF контролируемо, не повторять
  произвольно mutation после неопределённого сетевого результата.

### M3. Production разрешает cookies без Secure

- Код: `app/config.py:8`, `app/config.py:17`, `docker-compose.yml:31`.
- Воспроизведение: экземпляр с `APP_ENV=production` и `COOKIE_SECURE=false` успешно
  запущен; Set-Cookie не имеет Secure. Флаг одинаково используется для JWT и CSRF.
- Почему проблема: cookies могут передаваться по HTTP. HttpOnly и SameSite
  не заменяют защищённый транспорт. Атака зависит от deployment/сетевого доступа.
- Тест: `test_production_requires_secure_cookies`, cookie tests при обоих значениях
  настройки и live placeholder-server.
- Минимальное исправление: production validation должна требовать Secure;
  HTTPS на ingress остаётся обязательным отдельным условием.

### M4. Timing enumeration username

- Код: `app/services/auth.py:70` — short circuit `user is None or not verify_password(...)`.
- Воспроизведение: 12 чередующихся запросов каждого типа на локальном Docker HTTP.
  Медиана отсутствующего username — 20.48 мс; существующего с неверным паролем — 255.15 мс.
  В измерение входит также одинаковая операция получения CSRF.
- Ответы одинаковы: 401 и `Invalid username or password`; затраты Argon2 различаются.
- Почему проблема: облегчает определение существующих аккаунтов. Регистрация уже
  возвращает явный duplicate 409, поэтому это не единственный канал enumeration.
  Локальные числа не являются гарантированными production latency.
- Тест: `test_missing_user_performs_password_verification` и live timing probe.
- Минимальное исправление: выполнять verify относительно заранее подготовленного
  dummy Argon2 hash при отсутствующем пользователе. Не генерировать dummy hash на каждый запрос.

## LOW

### L1. Некорректные boundary inputs вызывают 500

- Код: `app/dependencies.py:77`; `app/routers/notes.py:20`, `app/routers/admin.py:21`.
- Воспроизведение: не-ASCII cookie/header вызывает TypeError в compare_digest(str, str).
  Авторизованный GET `/api/notes/9223372036854775808` и ещё больший integer дают 500
  на PostgreSQL. ID 0, -1 и строка корректно дают 422.
- Почему проблема: необработанные ошибки и лишние traceback вместо controlled 4xx;
  bypass authentication или ownership не обнаружен, массовый DoS не проверялся.
- Тесты: `test_non_ascii_csrf_is_controlled_forbidden`,
  `test_oversized_note_id_is_controlled`; большие ID повторены на PostgreSQL.
- Минимальное исправление: проверять формат CSRF перед сравнением; ограничить ID
  диапазоном используемого SQL Integer; аналогично валидировать числовой JWT sub.

### L2. Отсутствуют security/cache headers

- Код: `app/main.py:19`, `app/routers/pages.py:15`.
- Фактические ответы `/login`, `/notes`, `/api/auth/me`, `/api/notes` не содержат
  CSP, X-Content-Type-Options, Referrer-Policy, X-Frame-Options и Cache-Control.
  `frame-ancestors` тоже отсутствует, поскольку отсутствует CSP.
- Почему проблема: нет дополнительных ограничений XSS/framing, политики Referer и
  явного запрета хранения чувствительных ответов. Это недостаток защиты, не доказанная XSS.
- Тест: live header probe. Попытка cross-origin iframe в Chromium завершилась
  `chrome-error://chromewebdata/`; успешный clickjacking этим аудитом НЕ доказан.
- Минимальное исправление: подходящие CSP/frame-ancestors, nosniff, referrer policy,
  no-store для чувствительных API-ответов. HSTS на HTTP-localhost не требуется;
  его проверка и включение относятся к реальному HTTPS deployment.

### L3. Deployment и зависимости требуют доработки перед публичным запуском

- Код: `Dockerfile:1`, `docker-compose.yml:9`, `docker-compose.yml:10`, `pyproject.toml:10`.
- Проверено: процесс контейнера работает как root; PostgreSQL port публикуется без
  localhost-привязки; Compose содержит известный development password fallback.
  Версии зависимостей заданы диапазонами без lock-файла.
- Риск зависит от окружения. Это не подтверждённый container escape или доступ к БД извне.
- Инструменты: Bandit 1.9.4 — 0 findings; Ruff security rules — S105 на строке
  `access_token_cookie_name = "access_token"`, ложное срабатывание, это имя cookie.
- pip-audit 2.10.1 по точным пакетам runtime-образа сообщил 12 записей для pip 25.0.1
  (6 разных advisory IDs, часть вывода дублируется). В tools/dev окружении дополнительно
  сообщил advisory для pytest 8.4.2. Прямой exploit этих advisories не выполнялся;
  pytest не установлен в production Dockerfile. Локальный пакет проверялся кодом,
  а не как опубликованная PyPI-зависимость. Для остальных runtime-пакетов этот запуск
  pip-audit advisories не сообщил; это не гарантия отсутствия уязвимостей.
- Тест: inventory и вывод scanners, отдельного unit-теста нет.
- Минимальное исправление: обновить затронутые инструменты после проверки совместимости,
  зафиксировать воспроизводимые зависимости, использовать non-root и ограничить
  публикацию PostgreSQL в deployment. Development Compose не считать production-конфигурацией.

### L4. В каталоге сдачи присутствуют чувствительный .env и build-артефакты

- Места: `.env` (значения не приводятся), `.gitignore:1`, `.gitignore:5`,
  `.gitignore:8`, `.gitignore:9`, `.dockerignore:3`.
- Найдены `.env`, `app/__pycache__/`, `tests/__pycache__/`, `build/`,
  `private_notes_service.egg-info/`. Они существовали до изменений данного прохода.
- `.env` содержит непустые deployment credentials, JWT имеет 64 символа и отличается
  от placeholder. Поиск не обнаружил SQL dumps, PEM/private-key файлов, coverage/editor
  артефактов в проверяемом дереве. Предсказуемые audit/test credentials относятся только к тестам.
- `.gitignore` исключает основные найденные артефакты; `.dockerignore` исключает `.env`.
  На момент исходного аудита `.git` отсутствовал. Перед сдачей создан Git-репозиторий;
  `.env` игнорируется и не является tracked-файлом.
- Почему проблема: отправка всей папки/zip может включить секреты вопреки `.gitignore`.
  Наличие локального `.env` само по себе не доказывает его публикацию.
- Проверка: filesystem inventory и сравнение с ignore-файлами; теста нет.
- Минимальное исправление: подготовить чистый allowlisted архив; исключить `.env`
  и generated files, при фактической публикации секретов выполнить ротацию.

## GOOD — подтверждённые гарантии

- Неверный username и пароль: одинаковые 401/JSON; password/hash/JWT не появляются
  в успешных JSON authentication responses. JWT находится только в HttpOnly cookie.
- Malformed, неверная подпись, tampered sub другого пользователя, expired,
  отсутствующие exp/sub, нулевой/отрицательный/нечисловой sub: 401.
- Удалённый пользователь: 401, включая реально созданную и затем удалённую запись.
  Inactive пользователь: 403. Дополнительный подписанный `role=admin` claim
  не переопределяет роль user в БД.
- User A не может GET/PATCH/DELETE заметку B: 404 совпадает с missing;
  приватная запись после атак неизменна. Подмена owner_id/id/timestamps — 422.
- Все admin endpoints отклоняют ordinary user с 403 и anonymous с 401.
  Self-demotion/deactivation — 409. Повышение, понижение и деактивация действуют
  на уже выпущенный JWT; повторная активация восстанавливает доступ до exp.
- Admin через personal API по-прежнему ограничен владельцем. Через admin API
  может читать чужие notes; POST/PATCH/DELETE административных notes дают 405.
- CSRF: матрица 7 unsafe endpoints × 6 вариантов = 42 проверки. Нет обоих,
  только cookie, только header, mismatch и rotation — 403; совпадающие токены
  пропускают штатную операцию. GET не требует CSRF; CORS middleware отсутствует.
- Cookie HttpOnly/SameSite=Lax/Path=/ и условный Secure проверены; CSRF намеренно
  доступна JS. Chromium не видит JWT в document.cookie, storage пусты.
- DOM data flow: notes API → renderNotes → textContent; admin API → textCell →
  textContent; редактор использует value. Реальные img/onerror и script payload
  не создают исполняемые элементы. Username payload отклоняется ASCII-валидацией.
- SQL-like текст проходит roundtrip без выполнения. Queries используют SQLAlchemy
  expressions и bound parameters. Реальный PostgreSQL подтвердил FK 23503,
  username UNIQUE 23505, enum 22P02, NOT NULL 23502 и ix_notes_owner_id.
- Username 2/3/64/65 и Unicode/casefold; password 7/8/128/129; title empty/space/1/200/201;
  content empty/100000/100001 проверены. Forbidden fields, null и пустой PATCH
  покрыты regression/backend suite. API не раскрывает traceback при воспроизведённом 500.

## Что сохранено после hardening

- `tests/security_review/test_additional_regressions.py`: реальное удаление пользователя,
  недоверие role claim и проверка скрытия bound parameters в exception.
- `tests/security_review/test_attacks.py`: обычные regression tests для закрытых
  security findings.
- Этот отчёт. Другие файлы не редактировались.

Проверка основного baseline: `pytest --ignore=tests/security_review`.
Полный набор: `pytest`. Исправленные сценарии больше не используют `xfail`.
Одноразовые live/browser probes не являются частью финального test suite.

## Ограничения

Аудит выполнялся локально, на HTTP, PostgreSQL 17, Python 3.12 и Chromium.
Не проверялись production reverse proxy/TLS, внешняя доступность портов,
история до текущего единственного Git commit, резервные копии, нагрузочный DoS
и параллельные гонки авторизации.
SQLite использован для быстрых тестов; PostgreSQL constraints/live-сценарии
проверены отдельно. Формальный CSRF bypass без XSS/контроля origin не обнаружен.
Подделка sub без ключа не прошла; перенос действительного чужого bearer token
не рассматривается как алгоритмический обход подписи.
README-команды build/up/migrate/create_admin с отдельным project сработали.
Качество защиты не выводится из отсутствия findings у scanner.

## Исторические приоритеты

- Закрыты hardening pass: H1, H2, M1–M4, L1–L2.
- Перед упаковкой по-прежнему необходимо исключать локальный `.env` и generated
  artifacts (исторический L4).
- Обновление инструментов и воспроизводимость dependency resolution из L3 можно
  выполнять отдельно от текущего тестового задания.
- CAN LEAVE AS TECH DEBT для локального тестового: полноценная deployment-hardening,
  HTTPS/HSTS вне приложения, rate limiting, last-admin invariant, server-side отзыв
  JWT.
