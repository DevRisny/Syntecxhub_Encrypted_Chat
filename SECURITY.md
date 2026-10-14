# Security notes

## What is protected
| Threat | Defence |
|---|---|
| Someone reads the traffic (sniffing) | Every message is encrypted with AES-256-GCM. A test captures the real network bytes and checks that no text or name appears. |
| Someone changes a message | GCM authentication tag: any changed bit makes decryption fail and the connection is closed. |
| Someone records a message and sends it again (replay) | Strict message counter. Only the next expected counter is accepted. Tested with a proxy that duplicates a frame. |
| Dropping or re-ordering messages | Same counter check. |
| Reflecting a message back to its sender | Different key and nonce prefix for each direction. |
| Man-in-the-middle during key exchange | Both sides must prove they know the passphrase with an HMAC over the full handshake transcript. Without the passphrase an attacker cannot produce a valid tag. |
| Old traffic decrypted after a key leak | Ephemeral X25519 keys: every connection has fresh keys (forward secrecy for the session keys). |
| Nonce reuse (breaks AES-GCM) | 96-bit nonce = 4-byte per-direction prefix + 64-bit counter that only goes up. A new key is derived on every connection. |
| Guessing the passphrase from a captured handshake | scrypt (n=2^14) with a random salt per server start makes each guess slow. Use a long passphrase. |
| Memory abuse by huge or broken frames | Frame limit 64 KB, message limit 2000 characters, handshake and login timeouts, client limit, idle timeout. |
| Crashing the server with bad data | Every client runs in its own task, all protocol errors are caught. Garbage input is tested. |

## What is NOT protected (honest limits)
- **The passphrase is shared.** Anyone who knows it can join and read new messages. It is not a per-user login. Share it over a safe channel.
- **A weak passphrase can be guessed offline** by someone who recorded a handshake. The server requires at least 8 characters, but 4+ random words is much better.
- **The server sees plain text.** Encryption is between each client and the server, not end-to-end between users. The server decrypts, logs (optional) and re-encrypts for each receiver. Run the server on a machine you trust, or use `--no-log`.
- **The message log is plain text** (file mode 600). It is stored on the server only.
- **Metadata is visible**: who connects, when, and the size of messages (no padding).
- **No protection against a compromised client or server machine.**
- A passphrase is read from a hidden prompt or from `SYNTECXHUB_CHAT_PASSPHRASE`. It is never accepted as a command-line argument, because arguments show up in `ps`.
- Not audited. This is a learning project, built with the standard `cryptography` library and no custom primitives.

## Reporting
Open a GitHub issue (no secrets in it) or contact the author through the GitHub profile.
