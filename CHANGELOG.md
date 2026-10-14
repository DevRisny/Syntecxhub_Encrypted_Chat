# Changelog

## 1.0.0
- Asyncio TCP server and client, many clients at the same time
- Ephemeral X25519 key exchange (new keys for every connection, forward secrecy)
- Passphrase authentication of both sides (scrypt + HMAC over the handshake transcript)
- AES-256-GCM messages, one key per direction, counter-based nonces, replay/reorder/drop detection
- Server-side message log, join/leave notices, `/who`, input limits, timeouts
- `chat-server` and `chat-client` console commands
- 42 unit and integration tests (including a network sniffer test and a replay-attack test)
- ruff lint and format checks, GitHub Actions CI on Python 3.9 to 3.13
