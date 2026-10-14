"""Encrypted chat client: a small reusable class plus an interactive terminal UI."""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from typing import Any, Dict, List, Optional

from .channel import SecureChannel, client_handshake
from .crypto import CryptoError
from .protocol import ProtocolError
from .server import ENV_PASSPHRASE, get_passphrase


class ChatError(Exception):
    """Connection, login or protocol failure, with a message that is safe to show."""


class ChatClient:
    """Connects, authenticates, and exchanges encrypted messages."""

    def __init__(self, host: str, port: int, name: str, passphrase: str) -> None:
        self.host, self.port, self.name, self._passphrase = host, port, name, passphrase
        self.channel: Optional[SecureChannel] = None
        self.users: List[str] = []

    async def connect(self, timeout: float = 10.0) -> None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise ChatError(f"cannot connect to {self.host}:{self.port} ({exc})") from None
        try:
            session = await asyncio.wait_for(
                client_handshake(reader, writer, self._passphrase), timeout
            )
            self.channel = SecureChannel(reader, writer, session)
            await self.channel.send({"type": "join", "name": self.name})
            reply = await asyncio.wait_for(self.channel.recv(), timeout)
        except (CryptoError, ProtocolError) as exc:
            writer.close()
            raise ChatError(str(exc)) from None
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            writer.close()
            raise ChatError("server closed the connection or did not answer") from None
        if reply.get("type") == "error":
            writer.close()
            raise ChatError(str(reply.get("text", "login refused")))
        if reply.get("type") != "welcome":
            writer.close()
            raise ChatError("unexpected reply from server")
        self.users = list(reply.get("users", []))

    async def send_text(self, text: str) -> None:
        assert self.channel is not None
        await self.channel.send({"type": "msg", "text": text})

    async def request_users(self) -> None:
        assert self.channel is not None
        await self.channel.send({"type": "who"})

    async def receive(self) -> Dict[str, Any]:
        assert self.channel is not None
        return await self.channel.recv()

    async def close(self) -> None:
        if self.channel is None:
            return
        try:
            await self.channel.send({"type": "quit"})
        except Exception:
            pass
        self.channel.close()
        await self.channel.wait_closed()
        self.channel = None


# ------------------------------------------------------------------ terminal UI
HELP = "Commands: /who  list users   /help  this help   /quit  leave"


def format_incoming(message: Dict[str, Any]) -> Optional[str]:
    kind = message.get("type")
    if kind == "msg":
        stamp = time.strftime("%H:%M", time.localtime(float(message.get("ts", time.time()))))
        return f"[{stamp}] {message.get('from', '?')}: {message.get('text', '')}"
    if kind == "system":
        return f"* {message.get('text', '')}"
    if kind == "users":
        return "* online: " + ", ".join(message.get("users", []))
    if kind == "error":
        return f"! {message.get('text', '')}"
    return None


async def _reader_task(client: ChatClient) -> None:
    try:
        while True:
            line = format_incoming(await client.receive())
            if line:
                print("\r" + line + " " * 4, flush=True)
    except (asyncio.IncompleteReadError, ConnectionError):
        print("\n* connection closed by server", flush=True)
    except (CryptoError, ProtocolError) as exc:
        print(f"\n! secure channel error: {exc}", flush=True)


async def run_terminal(client: ChatClient) -> None:
    print(f"Connected as {client.name}. Online: {', '.join(client.users) or 'just you'}")
    print(HELP)
    reader = asyncio.create_task(_reader_task(client))
    loop = asyncio.get_running_loop()
    try:
        while not reader.done():
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:  # Ctrl+D
                break
            line = line.strip()
            if not line:
                continue
            if line in ("/quit", "/exit"):
                break
            if line == "/who":
                await client.request_users()
            elif line == "/help":
                print(HELP)
            elif line.startswith("/"):
                print("! unknown command, try /help")
            else:
                await client.send_text(line)
    except (ConnectionError, CryptoError):
        print("! connection lost")
    finally:
        reader.cancel()
        await client.close()
        print("Disconnected.")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="chat-client", description="Encrypted chat client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--name", "-n", required=True, help="your chat name")
    args = parser.parse_args(argv)
    passphrase = get_passphrase()
    if not passphrase:
        print(f"empty passphrase (or set {ENV_PASSPHRASE})", file=sys.stderr)
        return 2
    client = ChatClient(args.host, args.port, args.name, passphrase)

    async def run() -> None:
        await client.connect()
        await run_terminal(client)

    try:
        asyncio.run(run())
    except ChatError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nDisconnected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
