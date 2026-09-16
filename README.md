# GhostIndex

Веб-сервис архивной разведки по публичному индексу [Wayback Machine](https://web.archive.org/). Собирает CDX, классифицирует чувствительные пути, разбирает снимки на сигнатуры секретов и опционально подключает OpenAI-compatible LLM (Ollama, LM Studio, vLLM).

Использовать **только** по целям, на которые есть документальное разрешение. Сервис не ломает живые системы и работает с тем, что уже лежит в Internet Archive.

## Что умеет

- Регистрация с апрувом админа. Bootstrap-админ генерируется при старте (логин/пароль в консоли и в `data/.admin_credentials`).
- Проекты: `name`, `description`, `target` (несколько доменов), расписание, свои ключевые слова и расширения.
- Дашборд с критичностью находок.
- Кабинет: фото, пароль, почта, темы, Telegram/SMTP, LLM.

## Требования

- Python **3.11+** (на новой машине достаточно этого)
- либо **Docker** / Docker Compose

Debian / Kali / Ubuntu, если `python3` есть, а venv нет:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

## Запуск на любой машине

Клонировал — запустил. `python3 run.py` **сам** создаст `.venv` и поставит пакеты. Активировать venv руками не нужно.

```bash
git clone <URL-репозитория> wayback_tool
cd wayback_tool
python3 run.py
```

Открой **http://127.0.0.1:8787**. Логин админа — в терминале и в `data/.admin_credentials`.

Порт занят (часто Burp на 8080) — другой порт:

```bash
GHOSTINDEX_PORT=8787 python3 run.py
```

Чтобы админ **не** сменялся при каждом рестарте:

```bash
GHOSTINDEX_KEEP_ADMIN=true python3 run.py
```

Опционально скопируй `.env.example` → `.env` (SMTP и прочее). Без `.env` тоже стартует.

То же самое скриптом:

```bash
chmod +x ghostindex
./ghostindex
```

## Docker (ещё проще на чужой машине)

```bash
docker compose up --build
```

Сервис: http://127.0.0.1:8787  
Данные (БД, аватарки, админ-файл) живут в volume `ghostindex-data`. В compose включён `GHOSTINDEX_KEEP_ADMIN=true`, чтобы рестарт контейнера не сбрасывал админа.

Остановка:

```bash
docker compose down
```

## LLM

Кабинет → блок **LLM · OpenAI-compatible**: Base URL, API path `/v1/chat/completions`, модель, ключ. В карточке проекта — галки «разбор снимков» и «отсев ложных URL».

## Публикация в Git

Секреты (`data/`, `.env`, `.venv`) в git **не** попадают — они в `.gitignore`.

### Один раз на машине

```bash
sudo apt install -y git gh
gh auth login
```

### Первый push (ещё нет репозитория)

Из корня проекта:

```bash
cd /home/akuma0xdead/Projects/wayback_tool

git init
git branch -M main
git add .
git status
git commit -m "Initial commit: GhostIndex Wayback intelligence desk"

gh repo create ghostindex --private --source=. --remote=origin --push
```

`--private` — закрытый репозиторий. Публичный: замени на `--public`.

Имя `ghostindex` можно сменить. После `gh repo create` команда сама сделает `git push -u origin main` и напечатает URL.

### Если GitHub-репо уже создано руками

```bash
git init
git branch -M main
git add .
git commit -m "Initial commit: GhostIndex Wayback intelligence desk"
git remote add origin git@github.com:ТВОЙ_ЛОГИН/ghostindex.git
git push -u origin main
```

HTTPS вместо SSH:

```bash
git remote add origin https://github.com/ТВОЙ_ЛОГИН/ghostindex.git
git push -u origin main
```

### Проверка, что в коммит не утекли секреты

```bash
git ls-files | grep -E 'data/|\.env$|admin_credentials|\.venv' || echo "чисто"
```

Должно быть пусто (кроме разве что `data/.gitkeep`).

### Дальнейшие коммиты

```bash
git add -A
git status
git commit -m "Кратко: зачем изменение"
git push
```

## Стек

FastAPI · SQLite · APScheduler · httpx · Jinja2 · опционально LLM через Chat Completions.
