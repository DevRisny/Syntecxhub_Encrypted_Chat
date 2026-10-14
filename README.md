# Syntecxhub_Encrypted_Chat

[![CI](https://github.com/DevRisny/Syntecxhub_Encrypted_Chat/actions/workflows/ci.yml/badge.svg)](https://github.com/DevRisny/Syntecxhub_Encrypted_Chat/actions)
![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Crypto](https://img.shields.io/badge/crypto-X25519%20%2B%20AES--256--GCM-blue)

Project 1 of Week 2 in the **Syntecxhub Cyber Security Internship**: a **multi-client TCP chat** where every message is encrypted with **AES-256-GCM**. The session keys come from an **X25519 key exchange** that is authenticated with a **pre-shared passphrase**.

## Task checklist
| Requirement | Where |
|---|---|
| TCP client and server | `server.py`, `client.py` (asyncio) |
| AES-encrypted messages | `crypto.py` (AES-256-GCM) |
| Key exchange **or** pre-shared key | Both: X25519 exchange, authenticated with the pre-shared passphrase |
| Safe IV (nonce) usage | Counter-based unique nonces, new keys per connection, replay protection |
| Multiple clients | Any number of clients (default limit 50), broadcast + join/leave notices |
| Message logging | `chat_messages.log` on the server (`--log-file`, `--no-log`) |

## Quick start
```bash
pip install .                       # installs `chat-server` and `chat-client`
export SYNTECXHUB_CHAT_PASSPHRASE="correct horse battery"   # or type it when asked (hidden)

chat-server --port 5000             # terminal 1
chat-client --port 5000 -n alice    # terminal 2
chat-client --port 5000 -n bob      # terminal 3
```
Without installing: `PYTHONPATH=src python -m syntecxhub_chat.server` and `... .client`.

Client commands: `/who` list users, `/help`, `/quit`.

### Example (real output)
```
$ chat-client --port 5055 -n bob
Connected as bob. Online: alice, bob
[16:07] alice: hello from alice
* alice left

$ chat-client --port 5055 -n eve          # wrong passphrase
Error: handshake failed: wrong passphrase, or this is not a Syntecxhub chat server
```
Server side:
```
INFO alice joined from ('127.0.0.1', 44820)
INFO alice: hello from alice
WARNING rejected ('127.0.0.1', 59272): client failed passphrase authentication
```

## How it works
```
 client                                                   server
   | ---- ClientHello: X25519 public key + random ------->  |
   | <--- ServerHello: X25519 public key + random + salt -- |
   |   both: shared = X25519(...)                           |
   |   both: keys = HKDF-SHA256(shared, salt = hash(hellos))|
   |   both: psk  = scrypt(passphrase, salt)                |
   | ---- HMAC(psk, "client" + transcript) -------------->  |  server checks
   | <--- HMAC(psk, "server" + transcript) ---------------  |  client checks
   |                                                        |
   | ==== AES-256-GCM frames: counter | ciphertext | tag == |
```
1. **Key exchange.** Each side makes a fresh X25519 key pair for this connection only. The shared secret goes through HKDF to give two 256-bit keys (client-to-server and server-to-client) and two nonce prefixes.
2. **Authentication.** A plain Diffie-Hellman exchange can be attacked by a man-in-the-middle. So both sides send an HMAC, keyed from the passphrase, over the whole handshake transcript. An attacker without the passphrase cannot make a valid one, and the server never sends data to an unauthenticated client.
3. **Messages.** JSON messages are encrypted with AES-256-GCM. Wire format: `4-byte length | 8-byte counter | ciphertext | 16-byte tag`.

### Safe IV / nonce usage
AES-GCM breaks badly if a (key, nonce) pair is ever used twice. This project prevents that in layers:
- A **new key** is derived for every connection (fresh X25519 keys + random values).
- **One key per direction**, so both sides can count from 0 without a clash.
- The 12-byte nonce is `4-byte direction prefix + 8-byte counter`. The counter only goes up, so a nonce **cannot repeat** (a test checks this).
- The receiver accepts **only the next expected counter**. A replayed, dropped, re-ordered or reflected message is rejected and the connection is closed (tested with a proxy that duplicates a frame).
- Handshake data and direction are bound into GCM as associated data, so a frame cannot be moved to another session or direction.

## Project layout
```
src/syntecxhub_chat/
  crypto.py     key exchange, HKDF, passphrase auth, AES-GCM Session
  protocol.py   length-prefixed frames, JSON messages
  channel.py    handshake over the network, SecureChannel
  server.py     asyncio server, logging, limits
  client.py     ChatClient class + terminal UI
tests/          42 tests
```

## Tests
```bash
pip install -e . ruff
python -m unittest discover -s tests -v
ruff check . && ruff format --check .
```
The tests include: encryption round trip and tamper/replay/reorder/reflection detection, wrong passphrase, duplicate and invalid names, many concurrent clients, garbage and oversized input, a **network sniffer test** (no message text, name or passphrase appears in the captured bytes) and message logging.

## Limits (honest notes)
- It is encryption between each client and the **server**, not end-to-end between users. The server sees plain text (and logs it unless `--no-log`).
- One shared passphrase for the group, not per-user accounts.
- Use a long passphrase. See [SECURITY.md](SECURITY.md) for the full threat model.

## What I learned
Key exchange (X25519, HKDF), authenticated encryption (AES-GCM) and why nonce reuse is fatal, man-in-the-middle protection, replay protection, asyncio networking and concurrency, and testing security properties by sniffing real traffic.
