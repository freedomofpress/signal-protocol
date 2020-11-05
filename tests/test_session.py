import pytest

from tests.utils.sessions import run_interaction

from signal_protocol import curve, address, error, identity_key, protocol, session, session_cipher, state, storage

DEVICE_ID = 1


def test_basic_prekey_v3():
    alice_address = address.ProtocolAddress("+14151111111", DEVICE_ID)
    bob_address = address.ProtocolAddress("+14151111112", DEVICE_ID)

    alice_identity_key_pair = identity_key.IdentityKeyPair.generate()
    bob_identity_key_pair = identity_key.IdentityKeyPair.generate()

    alice_registration_id = 1 #TODO: generate these
    bob_registration_id = 2

    alice_store = storage.InMemSignalProtocolStore(alice_identity_key_pair, alice_registration_id)
    bob_store = storage.InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)

    bob_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_pair = curve.KeyPair.generate()

    bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key().serialize()

    bob_signed_pre_key_signature = bob_store.get_identity_key_pair() \
                                            .private_key() \
                                            .calculate_signature(bob_signed_pre_key_public)

    pre_key_id = 31337
    signed_pre_key_id = 22

    bob_pre_key_bundle = state.PreKeyBundle(
        bob_store.get_local_registration_id(),
        DEVICE_ID,
        pre_key_id,
        bob_pre_key_pair.public_key(),
        signed_pre_key_id,
        bob_signed_pre_key_pair.public_key(),
        bob_signed_pre_key_signature,
        bob_store.get_identity_key_pair().identity_key(),
    )

    assert alice_store.load_session(bob_address) is None

    # Below standalone function would make more sense as a method on alice_store?
    session.process_prekey_bundle(
        bob_address,
        alice_store,
        bob_pre_key_bundle,
    )

    assert alice_store.load_session(bob_address)
    assert alice_store.load_session(bob_address).session_version() == 3

    original_message = "Hobgoblins hold themselves to high standards of military honor"

    outgoing_message = session_cipher.message_encrypt(alice_store, bob_address, original_message)
    outgoing_message.message_type() == 3  # 3 == CiphertextMessageType::PreKey
    outgoing_message_wire = outgoing_message.serialize()

    # Now over to fake Bob for processing the first message

    incoming_message = protocol.PreKeySignalMessage.try_from(outgoing_message_wire)

    bob_prekey = state.PreKeyRecord(pre_key_id, bob_pre_key_pair)
    bob_store.save_pre_key(pre_key_id, bob_prekey)

    signed_prekey = state.SignedPreKeyRecord(
            signed_pre_key_id,
            42,
            bob_signed_pre_key_pair,
            bob_signed_pre_key_signature,
        )

    bob_store.save_signed_pre_key(signed_pre_key_id, signed_prekey)

    assert bob_store.load_session(alice_address) is None

    plaintext = session_cipher.message_decrypt(bob_store, alice_address, incoming_message)

    assert original_message == plaintext.decode('utf8')

    bobs_response = "Who watches the watchers?"

    assert bob_store.load_session(alice_address)

    bobs_session_with_alice = bob_store.load_session(alice_address)
    assert bobs_session_with_alice.session_version() == 3
    assert len(bobs_session_with_alice.alice_base_key()) == 32 + 1

    bob_outgoing = session_cipher.message_encrypt(bob_store, alice_address, bobs_response)
    assert bob_outgoing.message_type() == 2  # 2 == CiphertextMessageType::Whisper

    # Now back to fake alice

    alice_decrypts = session_cipher.message_decrypt(alice_store, bob_address, bob_outgoing)
    assert alice_decrypts.decode('utf8') == bobs_response

    run_interaction(alice_store, alice_address, bob_store, bob_address)

    alice_identity_key_pair = identity_key.IdentityKeyPair.generate()
    alice_registration_id = 1 #TODO: generate these
    alice_store = storage.InMemSignalProtocolStore(alice_identity_key_pair, alice_registration_id)

    bob_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key().serialize()

    bob_signed_pre_key_signature = bob_store.get_identity_key_pair() \
                                            .private_key() \
                                            .calculate_signature(bob_signed_pre_key_public)

    pre_key_id = 31337
    signed_pre_key_id = 22

    bob_pre_key_bundle = state.PreKeyBundle(
        bob_store.get_local_registration_id(),
        DEVICE_ID,
        pre_key_id + 1,
        bob_pre_key_pair.public_key(),
        signed_pre_key_id + 1,
        bob_signed_pre_key_pair.public_key(),
        bob_signed_pre_key_signature,
        bob_store.get_identity_key_pair().identity_key(),
    )

    bob_prekey = state.PreKeyRecord(pre_key_id + 1, bob_pre_key_pair)
    bob_store.save_pre_key(pre_key_id + 1, bob_prekey)

    signed_prekey = state.SignedPreKeyRecord(
            signed_pre_key_id + 1,
            42,
            bob_signed_pre_key_pair,
            bob_signed_pre_key_signature,
    )
    bob_store.save_signed_pre_key(signed_pre_key_id + 1, signed_prekey)

    session.process_prekey_bundle(
        bob_address,
        alice_store,
        bob_pre_key_bundle,
    )

    outgoing_message = session_cipher.message_encrypt(alice_store, bob_address, original_message)

    # TODO: Add to this assert the reason for failure: SignalProtocolError::UntrustedIdentity(alice_address.clone())
    with pytest.raises(error.SignalProtocolError):
        session_cipher.message_decrypt(bob_store, alice_address, outgoing_message)

    assert bob_store.save_identity(alice_address, alice_store.get_identity_key_pair().identity_key())

    decrypted = session_cipher.message_decrypt(bob_store, alice_address, outgoing_message)
    assert decrypted.decode('utf8') == original_message

    # Sign pre-key with wrong key
    bob_pre_key_bundle = state.PreKeyBundle(
        bob_store.get_local_registration_id(),
        DEVICE_ID,
        pre_key_id,
        bob_pre_key_pair.public_key(),
        signed_pre_key_id,
        bob_signed_pre_key_pair.public_key(),
        bob_signed_pre_key_signature,
        alice_store.get_identity_key_pair().identity_key(),
    )

    with pytest.raises(error.SignalProtocolError):
        session.process_prekey_bundle(
            bob_address,
            alice_store,
            bob_pre_key_bundle)
