import re
import sys
import asyncio
import aiohttp
import typing
import logging
from logging import handlers
from Core.nvd import *
from Core.tenable import *

class Telegram:

    def __init__(self, token):
        self.token = token

    def get_help(which = None):
        match which:
            case "cve":
                return """/CVE command:
            /cve <number>: to get cve info (Only 2025)
            /cve <cve-2024-14345> : to get CVE info
            /cve [critical | high | medium | low] : to get last 24 hours vulnerabilities based on provided severity"""
            case "report":
                return "Not Supported Yet!"
            case "news":
                return "Not Supported Yet!"
            case _:
                return """
                Commands:
                /cve
                /report
                /news
                For more use /help with command:
                /help [cve | report | news]"""


    async def send_telegram_message(session: aiohttp.ClientSession, chat_id: str, text: str):
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        if len(str(text)) > 4095:
            for x in range(0, len(str(text)), 4095):
                msg = str(text)[x:x+3000]
                payload = {"chat_id": chat_id, "text":f"``` {msg} ```", "parse_mode": "MarkdownV2"}
                async with session.post(url, json=payload) as resp:
                    if resp.status != 200:
                        logger.error("%s: %s", resp.status, await resp.text())
                    else:
                        logger.info("%s: %s", chat_id, text)
        else:
            payload = {"chat_id": chat_id, "text":f"``` {text} ```", "parse_mode": "MarkdownV2"}
            async with session.post(url, json=payload) as resp:
                if resp.status != 200:
                    logger.error("%s: %s", resp.status, await resp.text())
                else:
                    logger.info("%s: %s", chat_id, text)



    async def handle_telegram_command(session, chat_id, text):
        if text == "/start":
            await send_telegram_message(session, chat_id, "✅ Bot is running and listener is active.")
        elif text == "/status":
            await send_telegram_message(session, chat_id, f"🟢 Listening on {LISTEN_PORT}")
        elif text.startswith("/help"):
            temp = text.split(" ")
            if len(temp) < 2:
                await send_telegram_message(session, chat_id, get_help())
            elif len(temp) == 2:
                match temp[1]:
                    case "cve":
                        await send_telegram_message(session, chat_id, get_help("cve"))
                    case _:
                        await send_telegram_message(session, chat_id, "BAD Command")
            else:
                await send_telegram_message(session, chat_id, "Item Not Supported")

        elif text.startswith("/cve"):
            temp = text.split(" ")
            if len(temp) == 2:
                if temp[1].isnumeric():
                    vuln = Vulnerability()
                    cve = CVE()
                    data = await vuln.fetch_cve(f"CVE-2025-{temp[1]}")
                    if data:
                        data["Tenable-Plugin"] = await cve.fetch_cve_plugin(f"CVE-2025-{temp[1]}")
                        data["Tenable-CPE"] = await cve.fetch_cve_cpe(f"CVE-2025-{temp[1]}")
                        await send_telegram_message(session, chat_id, data)
                    else:
                        await send_telegram_message(session, chat_id, "No Result Found!")
                elif re.match(r"CVE-\d{4}-\d{3,5}", temp[1], re.IGNORECASE):
                    vuln = Vulnerability()
                    cve = CVE()
                    data = await vuln.fetch_cve(temp[1].upper())
                    if data:
                        data["Tenable"] = []
                        data["Tenable"].append({"Tenable-Plugin": await cve.fetch_cve_plugin(temp[1])})
                        data["Tenable"].append({"Tenable-CPE": await cve.fetch_cve_cpe(temp[1])})
                        await send_telegram_message(session, chat_id, data)
                    else:
                        await send_telegram_message(session, chat_id, "No Result Found!")
                elif temp[1].lower() in ["critical", "high", "medium", "low"]:
                    vuln = Vulnerability()
                    data = await vuln.fetch_cves(temp[1].upper()) #temp[1] is Severity
                    if data:
                        for item in data: #cause data is list of Vulns
                            await send_telegram_message(session, chat_id, item)
                    else:
                        await send_telegram_message(session, chat_id, "No CVE Recorded!")
                else:
                    await send_telegram_message(session, chat_id, "Wrong CVE. Try: /help cve")
            else:
                await send_telegram_message(session, chat_id, get_help("cve"))


    async def handle_telegram(session: aiohttp.ClientSession):
        """Poll Telegram updates and respond to commands like /status or /start."""
        offset = 0
        print("[+] Telegram command listener started.")
        while True:
            url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
            params = {"timeout": 30, "offset":offset}
            async with session.get(url, params=params) as resp:
                data = await resp.json()
                if data.get("result"):
                    #print(data)
                    for update in data.get("result", []):
                        offset = update["update_id"] + 1
                        if update.get("message"):
                            message = update.get("message", {})
                            if message.get("text"):
                                chat_id = message["chat"]["id"]
                                user = message["from"]
                                user_name = user.get("username") or user.get("first_name") or "NO NAME"
                                text = message.get("text")
                                logger.info("%s-%s: %s", user_name, chat_id, text)
                                await handle_telegram_command(session, chat_id, text)
                            if message.get("photo"):
                                chat_id = message["chat"]["id"]
                                await send_telegram_message(session, chat_id, "❌ NOT Supported ❌")
                            if message.get("audio"):
                                chat_id = message["chat"]["id"]
                                await send_telegram_message(session, chat_id, "❌ NOT Supported ❌")
                            if message.get("document"):
                                chat_id = message["chat"]["id"]
                                await send_telegram_message(session, chat_id, "❌ NOT Supported ❌")
                        if update.get("channel_post"):
                            post = update.get("channel_post", {})
                            if post.get("text"):
                                chat_id = post["chat"]["id"]
                                text = post.get("text")
                                await handle_telegram_command(session, chat_id, text)


                await asyncio.sleep(1)


    async def handle_socket(session: aiohttp.ClientSession):
        async def client_connected(reader, writer):
            await handle_client(reader, writer, session)

        server = await asyncio.start_server(client_connected, LISTEN_HOST, LISTEN_PORT)
        print(f"[+] Listening on {LISTEN_HOST}:{LISTEN_PORT}")
        async with server:
            await server.serve_forever()


    async def main():
        async with aiohttp.ClientSession() as session:
            await asyncio.gather(handle_telegram(session),
                                handle_socket(session),
                                )
