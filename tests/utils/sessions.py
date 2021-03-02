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


def run_interaction(
    alice_store: storage.InMemSignalProtocolStore,
    alice_address: address.ProtocolAddress,
    bob_store: storage.InMemSignalProtocolStore,
    bob_address: address.ProtocolAddress,
):

    alice_ptext = b"It's rabbit season"
    alice_message = session_cipher.message_encrypt(
        alice_store, bob_address, alice_ptext
    )

    assert alice_message.message_type() == 2  # CiphertextMessageType::Whisper => 2
    assert (
        session_cipher.message_decrypt(bob_store, alice_address, alice_message)
        == alice_ptext
    )

    bob_ptext = b"It's duck season"
    bob_message = session_cipher.message_encrypt(bob_store, alice_address, bob_ptext)

    assert bob_message.message_type() == 2  # CiphertextMessageType::Whisper => 2
    assert (
        session_cipher.message_decrypt(alice_store, bob_address, bob_message)
        == bob_ptext
    )

    for i in range(10):
        alice_ptext = f"A->B message {i}"
        alice_message = session_cipher.message_encrypt(
            alice_store, bob_address, alice_ptext.encode("utf8")
        )
        assert alice_message.message_type() == 2  # CiphertextMessageType::Whisper => 2
        assert session_cipher.message_decrypt(
            bob_store, alice_address, alice_message
        ) == alice_ptext.encode("utf8")

    for i in range(10):
        bob_ptext = f"B->A message {i}"
        bob_message = session_cipher.message_encrypt(
            bob_store, alice_address, bob_ptext.encode("utf8")
        )
        assert bob_message.message_type() == 2  # CiphertextMessageType::Whisper => 2
        assert session_cipher.message_decrypt(
            alice_store, bob_address, bob_message
        ) == bob_ptext.encode("utf8")

    alice_ooo_messages = []

    for i in range(10):
        alice_ptext = f"A->B OOO message {i}"
        alice_message = session_cipher.message_encrypt(
            alice_store, bob_address, alice_ptext.encode("utf8")
        )
        alice_ooo_messages.append((alice_ptext, alice_message))

    for i in range(10):
        alice_ptext = f"A->B post-OOO message {i}"
        alice_message = session_cipher.message_encrypt(
            alice_store, bob_address, alice_ptext.encode("utf8")
        )
        assert alice_message.message_type() == 2  # CiphertextMessageType::Whisper => 2
        assert session_cipher.message_decrypt(
            bob_store, alice_address, alice_message
        ) == alice_ptext.encode("utf8")

    for i in range(10):
        bob_ptext = f"B->A message post-OOO {i}"
        bob_message = session_cipher.message_encrypt(
            bob_store, alice_address, bob_ptext.encode("utf8")
        )
        assert bob_message.message_type() == 2  # CiphertextMessageType::Whisper => 2
        assert session_cipher.message_decrypt(
            alice_store, bob_address, bob_message
        ) == bob_ptext.encode("utf8")

    ## Now we check that messages can be decrypted when delivered out of order
    for (ptext, ctext) in alice_ooo_messages:
        assert session_cipher.message_decrypt(
            bob_store, alice_address, ctext
        ) == ptext.encode("utf8")


def initialize_sessions_v3():
    alice_identity = identity_key.IdentityKeyPair.generate()
    bob_identity = identity_key.IdentityKeyPair.generate()

    alice_base_key = curve.KeyPair.generate()

    bob_base_key = curve.KeyPair.generate()
    bob_ephemeral_key = bob_base_key

    alice_params = ratchet.AliceSignalProtocolParameters(
        alice_identity,
        alice_base_key,
        bob_identity.identity_key(),
        bob_base_key.public_key(),
        None,
        bob_ephemeral_key.public_key(),
    )

    alice_session = ratchet.initialize_alice_session(alice_params)

    bob_params = ratchet.BobSignalProtocolParameters(
        bob_identity,
        bob_base_key,
        None,
        bob_ephemeral_key,
        alice_identity.identity_key(),
        alice_base_key.public_key(),
    )

    bob_session = ratchet.initialize_bob_session(bob_params)

    return alice_session, bob_session


def run_session_interaction(alice_session, bob_session):
    alice_address = address.ProtocolAddress("+14159999999", 1)
    bob_address = address.ProtocolAddress("+14158888888", 1)

    alice_identity_key_pair = identity_key.IdentityKeyPair.generate()
    bob_identity_key_pair = identity_key.IdentityKeyPair.generate()

    alice_registration_id = 1  # TODO: generate these
    bob_registration_id = 2

    alice_store = storage.InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id
    )
    bob_store = storage.InMemSignalProtocolStore(
        bob_identity_key_pair, bob_registration_id
    )

    alice_store.store_session(bob_address, alice_session)
    bob_store.store_session(alice_address, bob_session)

    alice_plaintext = b"This is Alice's message"
    alice_ciphertext = session_cipher.message_encrypt(
        alice_store, bob_address, alice_plaintext
    )
    bob_decrypted = session_cipher.message_decrypt(
        bob_store, alice_address, alice_ciphertext
    )
    assert bob_decrypted == alice_plaintext

    bob_plaintext = b"This is Bob's reply"

    bob_ciphertext = session_cipher.message_encrypt(
        bob_store, alice_address, bob_plaintext
    )
    alice_decrypted = session_cipher.message_decrypt(
        alice_store, bob_address, bob_ciphertext
    )
    assert alice_decrypted == bob_plaintext

    ALICE_MESSAGE_COUNT = 50
    BOB_MESSAGE_COUNT = 50

    alice_messages = []

    for i in range(ALICE_MESSAGE_COUNT):
        ptext = f"смерть за смерть {i}"
        ctext = session_cipher.message_encrypt(
            alice_store, bob_address, ptext.encode("utf8")
        )
        alice_messages.append((ptext, ctext))

    random.shuffle(alice_messages)

    for i in range(ALICE_MESSAGE_COUNT // 2):
        ptext = session_cipher.message_decrypt(
            bob_store, alice_address, alice_messages[i][1]
        )
        assert ptext.decode("utf8") == alice_messages[i][0]

    bob_messages = []

    for i in range(BOB_MESSAGE_COUNT):
        ptext = f"Relax in the safety of your own delusions. {i}"
        ctext = session_cipher.message_encrypt(
            bob_store, alice_address, ptext.encode("utf8")
        )
        bob_messages.append((ptext, ctext))

    random.shuffle(bob_messages)

    for i in range(BOB_MESSAGE_COUNT // 2):
        ptext = session_cipher.message_decrypt(
            alice_store, bob_address, bob_messages[i][1]
        )
        assert ptext.decode("utf8") == bob_messages[i][0]

    for i in range(ALICE_MESSAGE_COUNT // 2, ALICE_MESSAGE_COUNT):
        ptext = session_cipher.message_decrypt(
            bob_store, alice_address, alice_messages[i][1]
        )
        assert ptext.decode("utf8") == alice_messages[i][0]

    for i in range(BOB_MESSAGE_COUNT // 2, BOB_MESSAGE_COUNT):
        ptext = session_cipher.message_decrypt(
            alice_store, bob_address, bob_messages[i][1]
        )
        assert ptext.decode("utf8") == bob_messages[i][0]


def is_session_id_equal(alice_store, alice_address, bob_store, bob_address) -> bool:
    return (
        alice_store.load_session(bob_address).alice_base_key()
        == bob_store.load_session(alice_address).alice_base_key()
    )


def create_pre_key_bundle(store):
    pre_key_pair = curve.KeyPair.generate()
    signed_pre_key_pair = curve.KeyPair.generate()

    signed_pre_key_public = signed_pre_key_pair.public_key().serialize()
    signed_pre_key_signature = (
        store.get_identity_key_pair()
        .private_key()
        .calculate_signature(signed_pre_key_public)
    )

    device_id = random.randint(1, 10000)
    pre_key_id = random.randint(1, 10000)
    signed_pre_key_id = random.randint(1, 10000)

    pre_key_bundle = state.PreKeyBundle(
        store.get_local_registration_id(),
        device_id,
        pre_key_id,
        pre_key_pair.public_key(),
        signed_pre_key_id,
        signed_pre_key_pair.public_key(),
        signed_pre_key_signature,
        store.get_identity_key_pair().identity_key(),
    )

    store.save_pre_key(pre_key_id, state.PreKeyRecord(pre_key_id, pre_key_pair))

    timestamp = random.randint(1, 10000)

    signed_prekey = state.SignedPreKeyRecord(
        signed_pre_key_id,
        timestamp,
        signed_pre_key_pair,
        signed_pre_key_signature,
    )
    store.save_signed_pre_key(signed_pre_key_id, signed_prekey)

    return pre_key_bundle
