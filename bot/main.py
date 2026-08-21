from __future__ import annotations

import asyncio
import logging
import os
from collections import defaultdict
from dataclasses import dataclass

import httpx
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandObject
from aiogram.types import BufferedInputFile, CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

API_BASE_URL = os.getenv("API_BASE_URL", "http://secval:8000/api").rstrip("/")
MAX_TARGETS = 100
CHAT_RESULT_LIMIT = 3
POLL_SECONDS = 5

MODULES = {
    "full": [
        "SSL Certificate Check", "SSL Certificate Hostname Mismatch", "SSLv3 Detection",
        "TLS 1.0 Detection", "TLS 1.1 Detection", "Response Code Check", "HSTS Security Check",
        "Security Headers Check", "Cookie Secure Flag", "Cookie HttpOnly Flag",
        "Laravel Debug Mode", "Node.js Debug Mode", "PHP Version Disclosure",
    ],
    "ssl": [
        "SSL Certificate Check", "SSL Certificate Hostname Mismatch", "SSLv3 Detection",
        "TLS 1.0 Detection", "TLS 1.1 Detection",
    ],
    "headers": ["HSTS Security Check", "Security Headers Check"],
    "cookies": ["Cookie Secure Flag", "Cookie HttpOnly Flag"],
}

SCAN_LABELS = {"full": "Full scan", "ssl": "SSL/TLS", "headers": "Security headers", "cookies": "Cookie security"}


@dataclass
class PendingScan:
    scan_type: str | None = None
    modules: list[str] | None = None


pending_scans: dict[int, PendingScan] = {}
router = Router()


def allowed_user(message: Message) -> bool:
    allowed = os.getenv("TELEGRAM_ALLOWED_USER_IDS", "")
    return bool(allowed) and message.from_user is not None and message.from_user.id in {
        int(value.strip()) for value in allowed.split(",") if value.strip().isdigit()
    }


def scan_menu() -> InlineKeyboardMarkup:
    buttons = [[InlineKeyboardButton(text="Full scan (13 checks)", callback_data="scan:full")]]
    buttons.extend(
        [InlineKeyboardButton(text=module, callback_data=f"module:{index}")]
        for index, module in enumerate(MODULES["full"])
    )
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def parse_targets(text: str) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    for raw in text.replace(",", "\n").splitlines():
        target = raw.strip()
        if target and target not in seen:
            targets.append(target)
            seen.add(target)
    return targets


def status_value(item: dict) -> str:
    return str(item.get("status", "info")).lower()


def domain_results(status: dict) -> dict[str, list[dict]]:
    grouped: defaultdict[str, list[dict]] = defaultdict(list)
    for items in (status.get("results") or {}).values():
        for item in items:
            target = item.get("target", "-")
            grouped[target].append(item)
    return dict(grouped)


def format_chat_result(status: dict) -> str:
    progress = status.get("progress", {})
    lines = [
        f"<b>Scan selesai</b>\nID: <code>{status.get('scan_id', '-')[:8]}</code>",
        f"Status: {status.get('status', '-')} | Module: "
        f"{progress.get('completed_modules', progress.get('completedModules', 0))}/"
        f"{progress.get('total_modules', progress.get('totalModules', 0))}",
    ]
    for target, items in domain_results(status).items():
        findings = [item for item in items if status_value(item) not in {"secure", "info"}]
        lines.append(f"\n<b>{target}</b>")
        if not findings:
            lines.append("✅ Tidak ada temuan pada pemeriksaan ini.")
            continue
        lines.append("Temuan:")
        for item in findings[:8]:
            name = item.get("vuln_name") or item.get("module") or "Temuan"
            lines.append(f"• {name}: {item.get('details', '-')}")
        if len(findings) > 8:
            lines.append(f"• ... dan {len(findings) - 8} temuan lain")
    if not domain_results(status):
        lines.append("Tidak ada hasil yang dapat ditampilkan.")
    return "\n".join(lines)


async def api_request(method: str, path: str, **kwargs) -> httpx.Response:
    async with httpx.AsyncClient(base_url=API_BASE_URL, timeout=60) as client:
        response = await client.request(method, path, **kwargs)
        response.raise_for_status()
        return response


async def run_scan(message: Message, scan_type: str, targets: list[str]) -> None:
    try:
        response = await api_request("POST", "/scans", json={"targets": targets, "modules": MODULES[scan_type]})
        scan_id = response.json()["scan_id"]
        await message.answer(f"⏳ {SCAN_LABELS[scan_type]} dimulai untuk {len(targets)} target.")
        while True:
            status_response = await api_request("GET", f"/scans/{scan_id}")
            status = status_response.json()
            if status.get("status") in {"done", "failed", "partial"}:
                break
            progress = status.get("progress", {})
            await asyncio.sleep(POLL_SECONDS)

        if len(targets) <= CHAT_RESULT_LIMIT:
            await message.answer(format_chat_result(status))
        else:
            summary_response = await api_request("GET", f"/scans/{scan_id}/summary")
            totals = summary_response.json().get("totals", {})
            await message.answer(
                f"<b>Batch scan selesai</b>\nTarget: {len(targets)}\n"
                f"Secure: {totals.get('secure', 0)} | Warning: {totals.get('warning', 0)} | "
                f"Insecure: {totals.get('insecure', 0)} | Error: {totals.get('error', 0)}"
            )
            report = await api_request("GET", f"/scans/{scan_id}/report.xlsx")
            await message.answer_document(
                BufferedInputFile(report.content, filename=f"secval-{scan_id[:8]}.xlsx"),
                caption="Laporan lengkap per domain dan module.",
            )
    except (httpx.HTTPError, KeyError) as exc:
        logger.exception("Scan failed: %s", exc)
        await message.answer("❌ Scan gagal diproses. Cek log backend untuk detailnya.")


async def run_module_scan(message: Message, module: str, targets: list[str]) -> None:
    try:
        response = await api_request("POST", "/scans", json={"targets": targets, "modules": [module]})
        scan_id = response.json()["scan_id"]
        await message.answer(f"⏳ {module} dimulai untuk {len(targets)} target.")
        while True:
            status = (await api_request("GET", f"/scans/{scan_id}")).json()
            if status.get("status") in {"done", "failed", "partial"}:
                break
            await asyncio.sleep(POLL_SECONDS)
        if len(targets) <= CHAT_RESULT_LIMIT:
            await message.answer(format_chat_result(status))
        else:
            report = await api_request("GET", f"/scans/{scan_id}/report.xlsx")
            await message.answer_document(
                BufferedInputFile(report.content, filename=f"secval-{scan_id[:8]}.xlsx"),
                caption=f"Laporan {module} lengkap per domain.",
            )
    except (httpx.HTTPError, KeyError) as exc:
        logger.exception("Module scan failed: %s", exc)
        await message.answer("❌ Scan gagal diproses. Cek log backend untuk detailnya.")


@router.message(Command("start"))
async def start_handler(message: Message) -> None:
    if not allowed_user(message):
        await message.answer("Akses bot belum diizinkan untuk akun Telegram ini.")
        return
    await message.answer("Pilih jenis pemeriksaan:", reply_markup=scan_menu())


@router.message(Command("scan"))
async def scan_handler(message: Message, command: CommandObject) -> None:
    if not allowed_user(message):
        await message.answer("Akses bot belum diizinkan untuk akun Telegram ini.")
        return
    await message.answer("Pilih jenis pemeriksaan:", reply_markup=scan_menu())


@router.callback_query(F.data.startswith("scan:"))
async def scan_choice_handler(callback: CallbackQuery) -> None:
    if callback.from_user.id not in {
        int(value.strip()) for value in os.getenv("TELEGRAM_ALLOWED_USER_IDS", "").split(",") if value.strip().isdigit()
    }:
        await callback.answer("Akses ditolak", show_alert=True)
        return
    scan_type = callback.data.split(":", 1)[1]
    pending_scans[callback.from_user.id] = PendingScan(scan_type)
    await callback.answer()
    try:
        await callback.message.edit_text(
            f"Mode: <b>{SCAN_LABELS[scan_type]}</b>\nKirim target satu per baris (maksimal {MAX_TARGETS})."
        )
    except TelegramBadRequest:
        await callback.message.answer(f"Kirim target satu per baris (maksimal {MAX_TARGETS}).")


@router.callback_query(F.data.startswith("module:"))
async def module_choice_handler(callback: CallbackQuery) -> None:
    allowed_ids = {
        int(value.strip()) for value in os.getenv("TELEGRAM_ALLOWED_USER_IDS", "").split(",")
        if value.strip().isdigit()
    }
    if callback.from_user.id not in allowed_ids:
        await callback.answer("Akses ditolak", show_alert=True)
        return
    index = int(callback.data.split(":", 1)[1])
    module = MODULES["full"][index]
    pending_scans[callback.from_user.id] = PendingScan(modules=[module])
    await callback.answer()
    try:
        await callback.message.edit_text(
            f"Mode: <b>{module}</b>\nKirim target satu per baris (maksimal {MAX_TARGETS})."
        )
    except TelegramBadRequest:
        await callback.message.answer(f"Kirim target satu per baris (maksimal {MAX_TARGETS}).")


@router.message(Command("fullscan"))
@router.message(Command("ssl"))
@router.message(Command("headers"))
@router.message(Command("cookies"))
async def shortcut_handler(message: Message, command: CommandObject) -> None:
    if not allowed_user(message):
        await message.answer("Akses bot belum diizinkan untuk akun Telegram ini.")
        return
    scan_type = {"fullscan": "full", "ssl": "ssl", "headers": "headers", "cookies": "cookies"}[command.command]
    targets = parse_targets(command.args or "")
    if not targets:
        pending_scans[message.from_user.id] = PendingScan(scan_type)
        await message.answer(f"Kirim target untuk {SCAN_LABELS[scan_type]}, satu per baris (maksimal {MAX_TARGETS}).")
        return
    if len(targets) > MAX_TARGETS:
        await message.answer(f"Maksimal {MAX_TARGETS} target per batch.")
        return
    await run_scan(message, scan_type, targets)


@router.message(F.text)
async def targets_handler(message: Message) -> None:
    if not allowed_user(message) or message.from_user.id not in pending_scans:
        return
    pending = pending_scans.pop(message.from_user.id)
    targets = parse_targets(message.text or "")
    if not targets:
        await message.answer("Target tidak ditemukan. Kirim satu domain per baris.")
        pending_scans[message.from_user.id] = pending
        return
    if len(targets) > MAX_TARGETS:
        await message.answer(f"Maksimal {MAX_TARGETS} target per batch. Kirim ulang daftar yang lebih kecil.")
        pending_scans[message.from_user.id] = pending
        return
    if pending.modules:
        await run_module_scan(message, pending.modules[0], targets)
    else:
        await run_scan(message, pending.scan_type or "full", targets)


async def main() -> None:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is required")
    if not os.getenv("TELEGRAM_ALLOWED_USER_IDS"):
        raise RuntimeError("TELEGRAM_ALLOWED_USER_IDS is required")
    bot = Bot(token=token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dispatcher = Dispatcher()
    dispatcher.include_router(router)
    await dispatcher.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())