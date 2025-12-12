# VulnBot (Nmap + AI) — Telegram/CLI

Инструмент для базового аудита безопасности цели (домен или IP): запускает сканирование `nmap` со скриптом `vulners`, собирает TLS/HTTPS сведения и проверяет ключевые security-заголовки, затем прогоняет результат через LLM (Groq API) и формирует HTML-отчёт.

> Важно: используйте только для легальных проверок (с разрешения владельца ресурса).

---

## Возможности

- Telegram-бот: принимает цель, показывает статус, отправляет HTML-отчёт.
- CLI-режим: запуск аудита из терминала.
- `nmap -sV` по портам `80,443` + `--script=vulners`.
- Парсинг XML nmap → «чистый» JSON (сервис/версия/порт + CVE).
- TLS-быстрая проверка (версия TLS, cipher, срок действия сертификата).
- Проверка HTTP security headers:
  - `X-Frame-Options`
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
- AI-анализ: выдаёт рекомендации в JSON:
  - `id` (CVE)
  - `priority` (High/Medium/Low)
  - `risk`, `steps`, `verify`, `references`
- Генерация красивого HTML-отчёта (включая сводку High/Medium/Low).

---

## Структура проекта

Примерно так (по файлам из кода):

- `bot.py` (или основной файл бота) — Telegram бот на aiogram, FSM + polling
- `nmap_scan.py` — запуск nmap, парсинг XML, TLS и security headers
- `ai.py` — запрос к Groq, нормализация/repair JSON-ответа, сохранение результатов
- `html_report.py` — сборка полного HTML-отчёта
- `styles.css` — стили для HTML (опционально; есть встроенный fallback)
- `config.py` — токены/ключи

Артефакты:
- `scans/` — nmap XML и «clean json»
- `report_<target>.html` — итоговый отчёт
- `recommendations.json` — результат AI (если сохраняете)
- `recommendations_raw.txt` — сырой ответ модели (для дебага)

---

## Требования

- Python 3.x
- Установленный `nmap` в системе (должен быть доступен как команда `nmap`)
- Python-пакеты:
  - `aiogram`
  - `requests`
  - `groq`

---

## Быстрый старт

### 1) Установка зависимостей

```
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip

pip install aiogram requests groq
```

> Если у вас есть `requirements.txt`, используйте его:
```
pip install -r requirements.txt
```

### 2) Конфиг

Создайте `config.py` (пример):

```
# config.py
BOT_TOKEN = "PASTE_TELEGRAM_BOT_TOKEN_HERE"

GROQ_API_KEY = "PASTE_GROQ_API_KEY_HERE"
GROQ_MODEL = "PASTE_MODEL_NAME_HERE"  # например: "llama-3.1-70b-versatile" (зависит от вашего аккаунта/доступа)
```

### 3) Запуск Telegram-бота

```
python3 bot.py
```

В Telegram:
1. `/start`
2. Отправьте домен или IP (можно с `http://` / `https://` — префикс будет убран)
3. Дождитесь сканирования и получите HTML-файл отчёта

### 4) Запуск CLI

Если в проекте есть CLI-скрипт (тот, что спрашивает `Введите IP или домен...`):

```
python3 cli.py
```

---

## Как это работает (pipeline)

1. Нормализация цели (убираются `http(s)://`, `/`, приводится к host/IP).
2. `nmap` сканирует `80,443` с определением версий (`-sV`) и `vulners`.
3. XML парсится в JSON:
   - hosts → ports → service/version → vulnerabilities (CVE/score/url/year).
4. Дополнительно:
   - TLS: версия, cipher, срок действия сертификата
   - HTTP: наличие 3 security headers
5. AI (Groq) превращает технический JSON в рекомендации (JSON).
6. Генерируется HTML-отчёт и отдаётся пользователю.

---

## Безопасность и дисклеймер

- Не сканируйте чужие ресурсы без явного разрешения.
- Результаты `vulners` и AI-рекомендации могут содержать ложные срабатывания или неточности — всегда перепроверяйте.
- Использование `verify=False` в HTTP-запросах отключает проверку TLS-сертификатов (нужно для сбора заголовков на проблемных хостах, но небезопасно для «боевого» клиента).

---
