import asyncio
import os
import tempfile
import unittest

from syntecxhub_chat.client import ChatClient, ChatError, format_incoming
from syntecxhub_chat.protocol import MAX_FRAME, ProtocolError, decode_message, read_frame
from syntecxhub_chat.server import ChatServer, chat_log, setup_logging

PASS = "correct horse battery"


class Tap:
    """A TCP proxy that records the bytes of every connection (what a sniffer would see)."""

    def __init__(self, target_port, duplicate_nth_client_frame=None):
        self.target_port = target_port
        self.seen = bytearray()
        self.duplicate_nth = duplicate_nth_client_frame
        self.port = 0
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self):
        self._server.close()  # do not wait: Python 3.12+ waits for open connections

    async def _handle(self, reader, writer):
        up_reader, up_writer = await asyncio.open_connection("127.0.0.1", self.target_port)

        async def pipe(src, dst, upstream):
            count = 0
            try:
                while True:
                    header = await src.readexactly(4)
                    body = await src.readexactly(int.from_bytes(header, "big"))
                    self.seen += header + body
                    dst.write(header + body)
                    if upstream:
                        count += 1
                        if self.duplicate_nth is not None and count == self.duplicate_nth:
                            dst.write(header + body)  # replay attack
                    await dst.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                dst.close()

        await asyncio.gather(pipe(reader, up_writer, True), pipe(up_reader, writer, False))


class ChatTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = ChatServer(PASS, port=0)
        await self.server.start()
        self.clients = []

    async def asyncTearDown(self):
        for client in self.clients:
            await client.close()
        await self.server.stop()

    async def connect(self, name, passphrase=PASS, port=None):
        client = ChatClient("127.0.0.1", port or self.server.port, name, passphrase)
        await client.connect()
        self.clients.append(client)
        return client

    async def recv(self, client, timeout=3):
        return await asyncio.wait_for(client.receive(), timeout)

    async def recv_type(self, client, kind):
        while True:
            message = await self.recv(client)
            if message["type"] == kind:
                return message


class MessagingTests(ChatTestCase):
    async def test_two_clients_exchange_messages(self):
        alice = await self.connect("alice")
        bob = await self.connect("bob")
        await alice.send_text("hi bob")
        message = await self.recv_type(bob, "msg")
        self.assertEqual((message["from"], message["text"]), ("alice", "hi bob"))
        await bob.send_text("hi alice")
        message = await self.recv_type(alice, "msg")
        self.assertEqual((message["from"], message["text"]), ("bob", "hi alice"))

    async def test_broadcast_reaches_all_other_clients(self):
        a, b, c = [await self.connect(n) for n in ("a", "b", "c")]
        await a.send_text("everyone")
        for other in (b, c):
            self.assertEqual((await self.recv_type(other, "msg"))["text"], "everyone")

    async def test_sender_does_not_get_own_message(self):
        a = await self.connect("a")
        b = await self.connect("b")
        await a.send_text("one")
        await b.send_text("two")
        message = await self.recv_type(a, "msg")
        self.assertEqual(message["text"], "two")

    async def test_unicode_and_emoji(self):
        a, b = await self.connect("a"), await self.connect("b")
        text = "வணக்கம் 👋 héllo"
        await a.send_text(text)
        self.assertEqual((await self.recv_type(b, "msg"))["text"], text)

    async def test_many_concurrent_clients(self):
        clients = [await self.connect(f"user{i}") for i in range(15)]
        await clients[0].send_text("ping")
        for other in clients[1:]:
            self.assertEqual((await self.recv_type(other, "msg"))["text"], "ping")
        self.assertEqual(len(self.server.users), 15)

    async def test_join_and_leave_notifications(self):
        a = await self.connect("a")
        b = await self.connect("b")
        self.assertIn("b joined", (await self.recv_type(a, "system"))["text"])
        await b.close()
        self.assertIn("b left", (await self.recv_type(a, "system"))["text"])

    async def test_who(self):
        a = await self.connect("a")
        await self.connect("b")
        await a.request_users()
        self.assertEqual((await self.recv_type(a, "users"))["users"], ["a", "b"])

    async def test_welcome_lists_users(self):
        await self.connect("a")
        b = await self.connect("b")
        self.assertEqual(b.users, ["a", "b"])

    async def test_too_long_message_refused(self):
        a = await self.connect("a")
        await a.send_text("x" * 3000)
        self.assertEqual((await self.recv_type(a, "error"))["type"], "error")

    async def test_name_can_be_reused_after_leaving(self):
        a = await self.connect("a")
        await a.close()
        await asyncio.sleep(0.1)
        await self.connect("a")


class LoginTests(ChatTestCase):
    async def test_wrong_passphrase_rejected(self):
        with self.assertRaises(ChatError):
            await self.connect("mallory", passphrase="not the passphrase")
        self.assertEqual(self.server.users, [])

    async def test_duplicate_name_rejected(self):
        await self.connect("alice")
        with self.assertRaises(ChatError) as ctx:
            await self.connect("alice")
        self.assertIn("taken", str(ctx.exception))

    async def test_invalid_names_rejected(self):
        for bad in ("", "has space", "x" * 25, "<script>", "a/b"):
            with self.assertRaises(ChatError, msg=bad):
                await self.connect(bad)

    async def test_connection_refused_is_clean_error(self):
        client = ChatClient("127.0.0.1", 1, "x", PASS)
        with self.assertRaises(ChatError):
            await client.connect(timeout=2)

    async def test_server_survives_garbage_connections(self):
        for payload in (b"GET / HTTP/1.1\r\n\r\n", b"\x00\x00\x00\x05hello", b"\xff" * 100, b""):
            _, writer = await asyncio.open_connection("127.0.0.1", self.server.port)
            writer.write(payload)
            await writer.drain()
            writer.close()
        await asyncio.sleep(0.1)
        alice = await self.connect("alice")
        self.assertEqual(alice.users, ["alice"])

    async def test_oversized_frame_header_rejected(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.server.port)
        writer.write((MAX_FRAME + 1).to_bytes(4, "big"))
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 3), b"")  # server hung up
        writer.close()

    async def test_server_full(self):
        server = ChatServer(PASS, port=0, max_clients=1)
        await server.start()
        try:
            first = ChatClient("127.0.0.1", server.port, "a", PASS)
            await first.connect()
            with self.assertRaises(ChatError):
                await ChatClient("127.0.0.1", server.port, "b", PASS).connect()
            await first.close()
        finally:
            await server.stop()


class WireSecurityTests(ChatTestCase):
    async def test_plaintext_never_on_the_wire(self):
        tap = Tap(self.server.port)
        await tap.start()
        try:
            sender = await self.connect("alice", port=tap.port)
            receiver = await self.connect("bob", port=tap.port)
            await sender.send_text("my secret launch code is 4242")
            await self.recv_type(receiver, "msg")
        finally:
            await tap.stop()
        self.assertGreater(len(tap.seen), 100)
        for needle in (b"secret", b"4242", b"launch", b"alice", b"bob", PASS.encode()):
            self.assertNotIn(needle, bytes(tap.seen))

    async def test_replayed_frame_ends_the_connection(self):
        tap = Tap(self.server.port, duplicate_nth_client_frame=4)  # hello, tag, join, msg
        await tap.start()
        try:
            sender = await self.connect("alice", port=tap.port)
            watcher = await self.connect("bob")
            await sender.send_text("pay once")
            self.assertEqual((await self.recv_type(watcher, "msg"))["text"], "pay once")
            # The duplicated frame carries an old counter: the server must drop alice.
            left = await self.recv_type(watcher, "system")
            while "left" not in left["text"]:
                left = await self.recv_type(watcher, "system")
            self.assertIn("alice left", left["text"])
        finally:
            await tap.stop()


class LogTests(unittest.IsolatedAsyncioTestCase):
    async def test_messages_are_logged(self):
        handle, path = tempfile.mkstemp(suffix=".log")
        os.close(handle)
        setup_logging(path, False)
        server = ChatServer(PASS, port=0)
        await server.start()
        try:
            a = ChatClient("127.0.0.1", server.port, "alice", PASS)
            await a.connect()
            await a.send_text("logged line")
            await asyncio.sleep(0.2)
            await a.close()
        finally:
            await server.stop()
            for h in list(chat_log.handlers):
                h.close()
                chat_log.removeHandler(h)
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
        os.unlink(path)
        self.assertIn("alice: logged line", content)


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    def test_decode_requires_typed_object(self):
        for bad in (b"[]", b"123", b'{"no":"type"}', b"\xff\xfe", b"not json"):
            with self.assertRaises(ProtocolError):
                decode_message(bad)
        self.assertEqual(decode_message(b'{"type":"msg"}')["type"], "msg")

    def test_format_incoming(self):
        self.assertIn("alice: hi", format_incoming({"type": "msg", "from": "alice", "text": "hi"}))
        self.assertEqual(format_incoming({"type": "system", "text": "x joined"}), "* x joined")
        self.assertIsNone(format_incoming({"type": "mystery"}))

    async def test_zero_length_frame_rejected(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x00\x00\x00\x00")
        with self.assertRaises(ProtocolError):
            await read_frame(reader)


if __name__ == "__main__":
    unittest.main()
