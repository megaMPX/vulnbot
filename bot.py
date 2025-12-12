#!/usr/bin/env python3

import asyncio
import json
import pathlib
import html
import urllib.parse
from datetime import datetime
import re

from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart
from aiogram.enums import ParseMode, ChatAction
from aiogram.client.default import DefaultBotProperties
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage

import nmap_scan
import ai
import config
import html_report

bot = Bot(token=config.BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher(storage=MemoryStorage())

class ScanStates(StatesGroup):
    waiting_for_target = State()

async def keep_typing(chat_id: int, stop_evt: asyncio.Event):
    try:
        while not stop_evt.is_set():
            await bot.send_chat_action(chat_id, ChatAction.TYPING)
            await asyncio.sleep(4.5)
    except asyncio.CancelledError:
        return
    except Exception:
        return

def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        p = urllib.parse.urlparse(raw)
        return p.netloc or p.path
    if "://" in raw:
        p = urllib.parse.urlparse(raw)
        return p.netloc or p.path
    return raw.rstrip("/")

@dp.message(CommandStart())
async def cmd_start(message: types.Message, state: FSMContext):
    await message.answer(
        "👋 Привет! Отправь домен или IP в формате:\n"
        "<code>scan.site.ru</code>\nили\n<code>192.168.0.1</code>\n\n"
        "Можно вставить с http/https — я сам уберу префикс.\n\n"
        "Я просканирую целевой сервер, найду уязвимости и пришлю красивый HTML-отчёт."
    )
    await state.set_state(ScanStates.waiting_for_target)

@dp.message(ScanStates.waiting_for_target)
async def process_target(message: types.Message, state: FSMContext):
    raw_target = message.text.strip()
    await state.clear()

    if not raw_target:
        await message.answer("⚠️ Пожалуйста, введи корректный домен или IP.")
        return

    target = normalize_target(raw_target)
    chat_id = message.chat.id

    status_msg = await message.answer(f"🔍 Подготовка к сканированию {html.escape(target)}...")

    stop_evt = asyncio.Event()
    typing_task = asyncio.create_task(keep_typing(chat_id, stop_evt))

    try:
        await bot.edit_message_text(
            f"🌐 Получаю основную информацию о сервере <b>{html.escape(target)}</b>...\n(сканирование может занять ~несколько минут)",
            chat_id=chat_id, message_id=status_msg.message_id
        )

        pathlib.Path("scans").mkdir(exist_ok=True)
        safe_name = target.replace(":", "_").replace("/", "_")
        prefix = f"scans/{safe_name}-vuln"
        xml_path = prefix + ".xml"
        json_path = f"scans/{safe_name}-clean.json"

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, nmap_scan.run_nmap, target, prefix)

        data = await loop.run_in_executor(None, nmap_scan.parse_xml, xml_path)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    except FileNotFoundError:
        stop_evt.set()
        typing_task.cancel()
        await bot.edit_message_text(
            "❌ Ошибка: nmap не найден на этом хосте. Установи nmap и попробуй снова.",
            chat_id=chat_id, message_id=status_msg.message_id
        )
        return
    except Exception as e:
        stop_evt.set()
        typing_task.cancel()
        await bot.edit_message_text(
            f"❌ Не удалось просканировать {html.escape(target)}:\n<code>{html.escape(str(e))}</code>\n"
            "Проверьте правильность домена/IP и доступность целевого хоста.",
            chat_id=chat_id, message_id=status_msg.message_id
        )
        return

    await bot.edit_message_text(
        "🔎 Сканирование завершено. Ищу уязвимости и анализирую данные (AI)…",
        chat_id=chat_id, message_id=status_msg.message_id
    )

    try:
        loop = asyncio.get_running_loop()
        result, raw_text = await loop.run_in_executor(None, ai.analyze_vulns, json_path)
    except Exception as e:
        stop_evt.set()
        typing_task.cancel()
        await bot.edit_message_text(
            f"❌ Ошибка при обращении к AI:\n<code>{html.escape(str(e))}</code>",
            chat_id=chat_id, message_id=status_msg.message_id
        )
        return

    stop_evt.set()
    typing_task.cancel()

    html_filename = f"report_{safe_name}.html"
    try:
        html_content = html_report.build_full_html_report(target, data, result, raw_text)
        with open(html_filename, "w", encoding="utf-8") as h:
            h.write(html_content)
    except Exception as e:
        await bot.edit_message_text(
            f"⚠️ Отчёт сформировать не удалось: {html.escape(str(e))}",
            chat_id=chat_id, message_id=status_msg.message_id
        )
        return

    await bot.edit_message_text(
        "✅ Анализ завершён.",
        chat_id=chat_id, message_id=status_msg.message_id
    )

    if result and result.get("recommendations"):
        recs = result["recommendations"]
        summary_lines = []
        for r in recs[:6]:
            summary_lines.append(f"• <b>{html.escape(r.get('id',''))}</b> — {html.escape(r.get('priority',''))}")
        summary_text = "<b>Краткое резюме найденных уязвимостей:</b>\n" + "\n".join(summary_lines)
        await message.answer(summary_text)
    elif raw_text:
        await message.answer("AI вернул текстовый отчёт (не JSON). Полный отчёт в HTML-файле.")

    await message.answer_document(types.FSInputFile(html_filename), caption="Отчёт аудита")

    #if pathlib.Path("recommendations.json").exists():
        #await message.answer_document(types.FSInputFile("recommendations.json"), caption="recommendations.json (AI)")

async def main():
    print("[+] Bot started")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())