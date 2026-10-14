import unittest

from syntecxhub_chat import crypto
from syntecxhub_chat.crypto import CryptoError, derive_session, new_client_hello, new_server_hello


def make_pair():
    """Run the key exchange in memory and return (client_session, server_session)."""
    salt = b"s" * crypto.SALT_LEN
    c_priv, c_hello = new_client_hello()
    s_priv, s_hello = new_server_hello(salt)
    c_pub = crypto.parse_client_hello(c_hello)
    s_pub, _ = crypto.parse_server_hello(s_hello)
    client, t1 = derive_session(c_priv, s_pub, c_hello, s_hello, is_client=True)
    server, t2 = derive_session(s_priv, c_pub, c_hello, s_hello, is_client=False)
    assert t1 == t2
    return client, server


class SessionTests(unittest.TestCase):
    def test_round_trip_both_directions(self):
        client, server = make_pair()
        self.assertEqual(server.decrypt(client.encrypt(b"hello server")), b"hello server")
        self.assertEqual(client.decrypt(server.encrypt(b"hello client")), b"hello client")

    def test_many_messages_in_order(self):
        client, server = make_pair()
        for i in range(50):
            self.assertEqual(server.decrypt(client.encrypt(b"m%d" % i)), b"m%d" % i)

    def test_ciphertext_hides_plaintext(self):
        client, _ = make_pair()
        frame = client.encrypt(b"top secret message")
        self.assertNotIn(b"secret", frame)

    def test_same_plaintext_gives_different_ciphertext(self):
        client, _ = make_pair()
        self.assertNotEqual(client.encrypt(b"same"), client.encrypt(b"same"))

    def test_nonce_counter_never_repeats(self):
        client, _ = make_pair()
        counters = [client.encrypt(b"x")[: crypto.COUNTER_LEN] for _ in range(200)]
        self.assertEqual(len(set(counters)), 200)

    def test_tampered_ciphertext_rejected(self):
        client, server = make_pair()
        frame = bytearray(client.encrypt(b"pay 10"))
        frame[-1] ^= 1
        with self.assertRaises(CryptoError):
            server.decrypt(bytes(frame))

    def test_tampered_counter_rejected(self):
        client, server = make_pair()
        client.encrypt(b"first")
        frame = bytearray(client.encrypt(b"second"))
        frame[7] ^= 1
        with self.assertRaises(CryptoError):
            server.decrypt(bytes(frame))

    def test_replay_rejected(self):
        client, server = make_pair()
        frame = client.encrypt(b"transfer")
        server.decrypt(frame)
        with self.assertRaises(CryptoError):
            server.decrypt(frame)

    def test_dropped_or_reordered_rejected(self):
        client, server = make_pair()
        client.encrypt(b"one")
        second = client.encrypt(b"two")
        with self.assertRaises(CryptoError):
            server.decrypt(second)

    def test_reflection_rejected(self):
        """A client message sent back to the client must not decrypt (separate keys)."""
        client, _ = make_pair()
        frame = client.encrypt(b"echo me")
        with self.assertRaises(CryptoError):
            client.decrypt(frame)

    def test_other_session_cannot_decrypt(self):
        a_client, _ = make_pair()
        _, b_server = make_pair()
        with self.assertRaises(CryptoError):
            b_server.decrypt(a_client.encrypt(b"x"))

    def test_too_short(self):
        _, server = make_pair()
        with self.assertRaises(CryptoError):
            server.decrypt(b"\x00" * 5)

    def test_failed_message_does_not_advance_counter(self):
        client, server = make_pair()
        frame = client.encrypt(b"ok")
        bad = bytearray(frame)
        bad[-1] ^= 1
        with self.assertRaises(CryptoError):
            server.decrypt(bytes(bad))
        self.assertEqual(server.decrypt(frame), b"ok")


class HandshakeDataTests(unittest.TestCase):
    def test_hello_parsing_rejects_garbage(self):
        with self.assertRaises(CryptoError):
            crypto.parse_client_hello(b"junk")
        with self.assertRaises(CryptoError):
            crypto.parse_server_hello(b"\x01" + b"\x00" * 10)
        _, hello = new_client_hello()
        with self.assertRaises(CryptoError):
            crypto.parse_client_hello(b"\x09" + hello[1:])  # unknown version

    def test_all_zero_public_key_rejected(self):
        priv, _ = new_client_hello()
        with self.assertRaises(CryptoError):
            derive_session(priv, b"\x00" * 32, b"c", b"s", is_client=True)

    def test_each_handshake_uses_fresh_keys(self):
        _, h1 = new_client_hello()
        _, h2 = new_client_hello()
        self.assertNotEqual(h1, h2)


class PassphraseTests(unittest.TestCase):
    def test_psk_depends_on_salt_and_passphrase(self):
        a = crypto.derive_psk("correct horse", b"1" * 16)
        self.assertEqual(a, crypto.derive_psk("correct horse", b"1" * 16))
        self.assertNotEqual(a, crypto.derive_psk("correct horse", b"2" * 16))
        self.assertNotEqual(a, crypto.derive_psk("wrong horse", b"1" * 16))
        self.assertEqual(len(a), 32)

    def test_empty_passphrase_rejected(self):
        with self.assertRaises(CryptoError):
            crypto.derive_psk("", b"1" * 16)

    def test_auth_tag_binds_role_and_transcript(self):
        psk = b"k" * 32
        tag = crypto.auth_tag(psk, b"client", b"T")
        self.assertTrue(crypto.check_auth_tag(psk, b"client", b"T", tag))
        self.assertFalse(crypto.check_auth_tag(psk, b"server", b"T", tag))
        self.assertFalse(crypto.check_auth_tag(psk, b"client", b"U", tag))
        self.assertFalse(crypto.check_auth_tag(b"x" * 32, b"client", b"T", tag))


if __name__ == "__main__":
    unittest.main()
