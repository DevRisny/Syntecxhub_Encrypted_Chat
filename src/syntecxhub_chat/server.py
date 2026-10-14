"""Multi-client encrypted chat server (asyncio)."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import os
import re
import secrets
import sys
import time
from typing import Dict, List, Optional

from .channel import SecureChannel, server_handshake
from .crypto import SALT_LEN, CryptoError, derive_psk
from .protocol import ProtocolError

ENV_PASSPHRASE = "SYNTECXHUB_CHAT_PASSPHRASE"
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,24}$")
MAX_TEXT = 2000
HANDSHAKE_TIMEOUT = 10.0
JOIN_TIMEOUT = 10.0
IDLE_TIMEOUT = 15 * 60

log = logging.getLogger("syntecxhub.chat.server")
chat_log = logging.getLogger("syntecxhub.chat.messages")


class ChatServer:
    """Accepts clients, authenticates them and relays encrypted messages between them."""

    def __init__(
        self,
        passphrase: str,
        host: str = "127.0.0.1",
        port: int = 5000,
        max_clients: int = 50,
        idle_timeout: float = IDLE_TIMEOUT,
    ) -> None:
        self.host = host
        self.port = port
        self.max_clients = max_clients
        self.idle_timeout = idle_timeout
        self._salt = secrets.token_bytes(SALT_LEN)
        self._psk = derive_psk(passphrase, self._salt)
        self._clients: Dict[str, SecureChannel] = {}
        self._server: Optional[asyncio.AbstractServer] = None

    # ----------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        sock = self._server.sockets[0]
        self.port = sock.getsockname()[1]  # real port when 0 was requested
        log.info("listening on %s:%d", self.host, self.port)

    async def serve_forever(self) -> None:
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
        for channel in list(self._clients.values()):
            channel.close()
        self._clients.clear()
        if self._server is not None:
            try:
                await asyncio.wait_for(self._server.wait_closed(), 2)
            except asyncio.TimeoutError:
                log.warning("some connections did not close in time")

    @property
    def users(self) -> List[str]:
        return sorted(self._clients)

    # ------------------------------------------------------------------ per client
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        name: Optional[str] = None
        channel: Optional[SecureChannel] = None
        try:
            if len(self._clients) >= self.max_clients:
                log.warning("rejected %s: server full", peer)
                return
            session = await asyncio.wait_for(
                server_handshake(reader, writer, self._psk, self._salt), HANDSHAKE_TIMEOUT
            )
            channel = SecureChannel(reader, writer, session)
            name = await asyncio.wait_for(self._join(channel), JOIN_TIMEOUT)
            if name is None:
                return
            log.info("%s joined from %s", name, peer)
            self._broadcast({"type": "system", "text": f"{name} joined"}, exclude=name)
            await self._loop(name, channel)
        except asyncio.TimeoutError:
            log.warning("timeout from %s", peer)
        except (CryptoError, ProtocolError) as exc:
            log.warning("rejected %s: %s", peer, exc)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception:  # keep the server alive whatever one client does
            log.exception("unexpected error with %s", peer)
        finally:
            if name is not None and self._clients.get(name) is channel:
                del self._clients[name]
                log.info("%s left", name)
                self._broadcast({"type": "system", "text": f"{name} left"})
            if channel is not None:
                channel.close()
            else:
                writer.close()

    async def _join(self, channel: SecureChannel) -> Optional[str]:
        hello = await channel.recv()
        name = hello.get("name")
        if hello.get("type") != "join" or not isinstance(name, str) or not NAME_RE.match(name):
            await channel.send(
                {"type": "error", "text": "invalid name (1-24 of A-Z a-z 0-9 _ . -)"}
            )
            return None
        if name in self._clients:
            await channel.send({"type": "error", "text": f"name '{name}' is already taken"})
            return None
        self._clients[name] = channel
        await channel.send({"type": "welcome", "users": self.users})
        return name

    async def _loop(self, name: str, channel: SecureChannel) -> None:
        while True:
            message = await asyncio.wait_for(channel.recv(), self.idle_timeout)
            kind = message.get("type")
            if kind == "msg":
                text = message.get("text")
                if not isinstance(text, str) or not text.strip():
                    continue
                if len(text) > MAX_TEXT:
                    await channel.send(
                        {"type": "error", "text": f"message too long (max {MAX_TEXT})"}
                    )
                    continue
                chat_log.info("%s: %s", name, text)
                self._broadcast(
                    {"type": "msg", "from": name, "text": text, "ts": time.time()}, exclude=name
                )
            elif kind == "who":
                await channel.send({"type": "users", "users": self.users})
            elif kind == "quit":
                return
            else:
                await channel.send({"type": "error", "text": "unknown message type"})

    def _broadcast(self, message: dict, exclude: Optional[str] = None) -> None:
        for other, channel in list(self._clients.items()):
            if other == exclude:
                continue
            try:
                channel.send_nowait(message)
            except Exception:
                log.debug("could not queue message for %s", other)


# ---------------------------------------------------------------------------- CLI
def setup_logging(log_file: Optional[str], verbose: bool) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    root = logging.getLogger("syntecxhub.chat")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(fmt)
    root.addHandler(console)
    if log_file:
        # Message log: who said what and when. Stored on the server only, as plain text.
        handler = logging.FileHandler(log_file, encoding="utf-8")
        handler.setFormatter(fmt)
        handler.setLevel(logging.INFO)
        chat_log.addHandler(handler)
        try:
            os.chmod(log_file, 0o600)
        except OSError:
            pass


def get_passphrase(confirm: bool = False) -> str:
    value = os.environ.get(ENV_PASSPHRASE)
    if value:
        return value
    value = getpass.getpass("Chat passphrase: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != value:
        raise SystemExit("passphrases do not match")
    return value


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="chat-server", description="Encrypted multi-client chat server"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="address to listen on (default 127.0.0.1)"
    )
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument(
        "--log-file", default="chat_messages.log", help="message log (default chat_messages.log)"
    )
    parser.add_argument("--no-log", action="store_true", help="do not write the message log")
    parser.add_argument("--max-clients", type=int, default=50)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    passphrase = get_passphrase(confirm=True)
    if len(passphrase) < 8:
        print("passphrase must have at least 8 characters", file=sys.stderr)
        return 2
    setup_logging(None if args.no_log else args.log_file, args.verbose)
    server = ChatServer(passphrase, args.host, args.port, args.max_clients)

    async def run() -> None:
        await server.start()
        print(f"Encrypted chat server on {args.host}:{server.port}  (Ctrl+C to stop)")
        await server.serve_forever()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except OSError as exc:
        print(f"cannot start server: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
