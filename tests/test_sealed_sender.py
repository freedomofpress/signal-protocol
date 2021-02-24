import pytest

from signal_protocol.address import ProtocolAddress
from signal_protocol.curve import KeyPair
from signal_protocol.error import SignalProtocolException
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.sealed_sender import (
    ServerCertificate,
    SenderCertificate,
    sealed_sender_encrypt,
    sealed_sender_decrypt,
)
from signal_protocol.session import process_prekey_bundle
from signal_protocol.storage import InMemSignalProtocolStore

from tests.utils.sessions import create_pre_key_bundle


def test_server_cert():
    trust_root = KeyPair.generate()
    server_key = KeyPair.generate()
    server_cert = ServerCertificate(
        1, server_key.public_key(), trust_root.private_key()
    )
    serialized_server_cert = server_cert.serialized()

    recovered_server_cert = ServerCertificate.deserialize(serialized_server_cert)
    assert recovered_server_cert.validate(trust_root.public_key())

    cert_bits = len(serialized_server_cert) * 8

    for bit in range(cert_bits):
        # flip bit
        edit_point = bit // 8
        serialized_server_cert = (
            serialized_server_cert[:edit_point]
            + bytes([serialized_server_cert[edit_point] ^ 0x01 << (bit % 8)])
            + serialized_server_cert[edit_point + 1 :]
        )

        # either the cert should not validate, or it should not even create
        # a valid ServerCertificate object
        try:
            cert = ServerCertificate.deserialize(serialized_server_cert)
            assert not cert.validate(trust_root.public_key())
        except SignalProtocolException as e:
            assert (
                "protobuf encoding was invalid" in str(e)
                or "failed to decode protobuf" in str(e)
                or "bad key type" in str(e)
            )

        # flip bit back
        serialized_server_cert = (
            serialized_server_cert[:edit_point]
            + bytes([serialized_server_cert[edit_point] ^ 0x01 << (bit % 8)])
            + serialized_server_cert[edit_point + 1 :]
        )


def test_sender_cert():
    trust_root = KeyPair.generate()
    server_key = KeyPair.generate()
    key = KeyPair.generate()
    server_cert = ServerCertificate(
        1, server_key.public_key(), trust_root.private_key()
    )

    device_id = 2
    expiration = 1234567

    sender_cert = SenderCertificate(
        "sender_uuid",
        "sender_e164",
        key.public_key(),
        device_id,
        expiration,
        server_cert,
        server_key.private_key(),
    )

    assert sender_cert.validate(trust_root.public_key(), expiration)
    assert not sender_cert.validate(trust_root.public_key(), expiration + 1)

    serialized_server_cert = sender_cert.serialized()
    cert_bits = len(serialized_server_cert) * 8

    for bit in range(cert_bits):
        # flip bit
        edit_point = bit // 8
        serialized_server_cert = (
            serialized_server_cert[:edit_point]
            + bytes([serialized_server_cert[edit_point] ^ 0x01 << (bit % 8)])
            + serialized_server_cert[edit_point + 1 :]
        )

        # either the cert should not validate, or it should not even create
        # a valid SenderCertificate object
        try:
            cert = SenderCertificate.deserialize(serialized_server_cert)
            assert not cert.validate(trust_root.public_key(), expiration)
        except SignalProtocolException as e:
            assert (
                "protobuf encoding was invalid" in str(e)
                or "failed to decode protobuf" in str(e)
                or "bad key type" in str(e)
            )

        # flip bit back
        serialized_server_cert = (
            serialized_server_cert[:edit_point]
            + bytes([serialized_server_cert[edit_point] ^ 0x01 << (bit % 8)])
            + serialized_server_cert[edit_point + 1 :]
        )


def test_sealed_sender_happy():
    alice_device_id = 2
    bob_device_id = 3

    alice_e164 = "alice_e164"
    bob_e164 = "bob_e164"
    alice_uuid = "alice_uuid"
    bob_uuid = "bob_uuid"

    alice_identity_key_pair = IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_store = InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id
    )
    alice_pubkey = alice_identity_key_pair.public_key()

    bob_identity_key_pair = IdentityKeyPair.generate()
    bob_registration_id = 2
    bob_store = InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)
    bob_uuid_address = ProtocolAddress(bob_uuid, bob_device_id)

    bob_pre_key_bundle = create_pre_key_bundle(bob_store)

    process_prekey_bundle(
        bob_uuid_address,
        alice_store,
        bob_pre_key_bundle,
    )

    trust_root = KeyPair.generate()
    server_key = KeyPair.generate()
    server_cert = ServerCertificate(
        1, server_key.public_key(), trust_root.private_key()
    )

    expiration = 1234567
    sender_cert = SenderCertificate(
        alice_uuid,
        alice_e164,
        alice_pubkey,
        alice_device_id,
        expiration,
        server_cert,
        server_key.private_key(),
    )

    alice_plaintext = b"teehee"
    alice_ciphertext = sealed_sender_encrypt(
        bob_uuid_address, sender_cert, alice_plaintext, alice_store
    )

    bob_plaintext = sealed_sender_decrypt(
        alice_ciphertext,
        trust_root.public_key(),
        expiration - 1,
        bob_e164,
        bob_uuid,
        bob_device_id,
        bob_store,
    )

    assert bob_plaintext.message() == alice_plaintext
    assert bob_plaintext.sender_uuid() == alice_uuid
    assert bob_plaintext.sender_e164() == alice_e164
    assert bob_plaintext.device_id() == alice_device_id


def test_sealed_sender_expired_cert():
    alice_device_id = 2
    bob_device_id = 3

    alice_e164 = "alice_e164"
    bob_e164 = "bob_e164"
    alice_uuid = "alice_uuid"
    bob_uuid = "bob_uuid"

    alice_identity_key_pair = IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_store = InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id
    )
    alice_pubkey = alice_identity_key_pair.public_key()

    bob_identity_key_pair = IdentityKeyPair.generate()
    bob_registration_id = 2
    bob_store = InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)
    bob_uuid_address = ProtocolAddress(bob_uuid, bob_device_id)

    bob_pre_key_bundle = create_pre_key_bundle(bob_store)

    process_prekey_bundle(
        bob_uuid_address,
        alice_store,
        bob_pre_key_bundle,
    )

    trust_root = KeyPair.generate()
    server_key = KeyPair.generate()
    server_cert = ServerCertificate(
        1, server_key.public_key(), trust_root.private_key()
    )

    expiration = 1234567
    sender_cert = SenderCertificate(
        alice_uuid,
        alice_e164,
        alice_pubkey,
        alice_device_id,
        expiration,
        server_cert,
        server_key.private_key(),
    )

    alice_plaintext = b"teehee"
    alice_ciphertext = sealed_sender_encrypt(
        bob_uuid_address, sender_cert, alice_plaintext, alice_store
    )

    with pytest.raises(SignalProtocolException, match="invalid sealed sender"):
        sealed_sender_decrypt(
            alice_ciphertext,
            trust_root.public_key(),
            expiration + 1,
            bob_e164,
            bob_uuid,
            bob_device_id,
            bob_store,
        )


def test_sealed_sender_invalid_trust_root():
    alice_device_id = 2
    bob_device_id = 3

    alice_e164 = "alice_e164"
    bob_e164 = "bob_e164"
    alice_uuid = "alice_uuid"
    bob_uuid = "bob_uuid"

    alice_identity_key_pair = IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_store = InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id
    )
    alice_pubkey = alice_identity_key_pair.public_key()

    bob_identity_key_pair = IdentityKeyPair.generate()
    bob_registration_id = 2
    bob_store = InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)
    bob_uuid_address = ProtocolAddress(bob_uuid, bob_device_id)

    bob_pre_key_bundle = create_pre_key_bundle(bob_store)

    process_prekey_bundle(
        bob_uuid_address,
        alice_store,
        bob_pre_key_bundle,
    )

    trust_root = KeyPair.generate()
    server_key = KeyPair.generate()
    server_cert = ServerCertificate(
        1, server_key.public_key(), trust_root.private_key()
    )

    expiration = 1234567
    sender_cert = SenderCertificate(
        alice_uuid,
        alice_e164,
        alice_pubkey,
        alice_device_id,
        expiration,
        server_cert,
        server_key.private_key(),
    )

    alice_plaintext = b"teehee"
    alice_ciphertext = sealed_sender_encrypt(
        bob_uuid_address, sender_cert, alice_plaintext, alice_store
    )

    invalid_trust_root = KeyPair.generate()

    with pytest.raises(SignalProtocolException, match="invalid sealed sender"):
        sealed_sender_decrypt(
            alice_ciphertext,
            invalid_trust_root.public_key(),
            expiration + 1,
            bob_e164,
            bob_uuid,
            bob_device_id,
            bob_store,
        )
