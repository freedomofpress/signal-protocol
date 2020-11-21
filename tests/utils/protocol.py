import random

from signal_protocol import (
    curve,
    address,
    error,
    identity_key,
    protocol,
    ratchet,
    session,
    session_cipher,
    state,
    storage,
)


def create_signal_message():
    mac_key = bytes(32)
    ciphertext = bytes(32)

    sender_ratchet_key_pair = curve.KeyPair.generate()
    sender_identity_key_pair = identity_key.IdentityKey(
        curve.KeyPair.generate().public_key().serialize()
    )
    receiver_identity_key_pair = identity_key.IdentityKey(
        curve.KeyPair.generate().public_key().serialize()
    )

    return protocol.SignalMessage(
        3,
        mac_key,
        sender_ratchet_key_pair.public_key(),
        42,
        41,
        ciphertext,
        sender_identity_key_pair,
        receiver_identity_key_pair,
    )


def assert_signal_message_equals(message1, message2):
    assert message1.message_version() == message2.message_version()
    assert message1.sender_ratchet_key() == message2.sender_ratchet_key()
    assert message1.counter() == message2.counter()
    assert message1.body() == message2.body()
    assert message1.serialized() == message2.serialized()
