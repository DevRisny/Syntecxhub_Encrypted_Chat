"""Handshake over the network and the encrypted channel used after it."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from typing import Any, Dict

from .crypto import (
    AuthError,
    CryptoError,
    Session,
    auth_tag,
    check_auth_tag,
    derive_psk,
    derive_session,
    new_client_hello,
    new_server_hello,
    parse_client_hello,
    parse_server_hello,
)
from .protocol import decode_message, encode_message, read_frame, write_frame


async def server_handshake(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, psk: bytes, salt: bytes
) -> Session:
    """Server side: exchange keys, verify that the client knows the passphrase."""
    client_hello = await read_frame(reader)
    client_public = parse_client_hello(client_hello)
    private, server_hello = new_server_hello(salt)
    write_frame(writer, server_hello)
    await writer.drain()
    session, transcript = derive_session(
        private, client_public, client_hello, server_hello, is_client=False
    )
    client_tag = await read_frame(reader)
    if not check_auth_tag(psk, b"client", transcript, client_tag):
        raise AuthError("client failed passphrase authentication")
    write_frame(writer, auth_tag(psk, b"server", transcript))
    await writer.drain()
    return session


async def client_handshake(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, passphrase: str
) -> Session:
    """Client side: exchange keys, prove the passphrase, verify the server too."""
    private, client_hello = new_client_hello()
    write_frame(writer, client_hello)
    await writer.drain()
    try:
        server_hello = await read_frame(reader)
        server_public, salt = parse_server_hello(server_hello)
        psk = derive_psk(passphrase, salt)
        session, transcript = derive_session(
            private, server_public, client_hello, server_hello, is_client=True
        )
        write_frame(writer, auth_tag(psk, b"client", transcript))
        await writer.drain()
        server_tag = await read_frame(reader)
    except (asyncio.IncompleteReadError, ConnectionError):
        raise AuthError(
            "handshake failed: wrong passphrase, or this is not a Syntecxhub chat server"
        ) from None
    if not check_auth_tag(psk, b"server", transcript, server_tag):
        raise AuthError("server failed passphrase authentication")
    return session


class SecureChannel:
    """Sends and receives encrypted JSON messages after a successful handshake."""

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session: Session
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._session = session

    def send_nowait(self, message: Dict[str, Any]) -> None:
        """Encrypt and queue a message. There is no await between encrypting and writing,
        so message counters always leave in order, even with many tasks sending."""
        write_frame(self._writer, self._session.encrypt(encode_message(message)))

    async def drain(self) -> None:
        await self._writer.drain()

    async def send(self, message: Dict[str, Any]) -> None:
        self.send_nowait(message)
        await self.drain()

    async def recv(self) -> Dict[str, Any]:
        frame = await read_frame(self._reader)
        try:
            return decode_message(self._session.decrypt(frame))
        except CryptoError:
            raise

    def close(self) -> None:
        with suppress(Exception):
            self._writer.close()

    async def wait_closed(self) -> None:
        with suppress(Exception):
            await self._writer.wait_closed()
