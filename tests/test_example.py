from signal_protocol import curve, identity_key, storage, state


def test_example_doc():
    # Each client must generate a long-term identity key pair.
    # This should be stored somewhere safe and persistent.
    identity_key_pair = identity_key.IdentityKeyPair.generate()

    # Clients must generate prekeys. The example here is generating a
    # single prekey, but clients will generate many as they are one-time use
    # and consumed when a message from a new chat participant is sent. See issue #7.
    pre_key_pair = curve.KeyPair.generate()

    # Clients must generate a registration_id and store it somewhere safe and persistent.
    registration_id = 12  # TODO generate (not yet supported in upstream crate)

    # The InMemSignalProtocolStore is a single object which provide the four storage
    # interfaces required: IdentityKeyStore (for one's own identity key state and the (public)
    # identity keys for other chat participants), PreKeyStore (for one's own prekey state),
    # SignedPreKeyStore (for one's own signed prekeys), and SessionStore (for established sessions
    # with chat participants).
    store = storage.InMemSignalProtocolStore(identity_key_pair, registration_id)

    # Clients should also generate a signed prekey.
    signed_pre_key_pair = curve.KeyPair.generate()
    serialized_signed_pre_pub_key = signed_pre_key_pair.public_key().serialize()
    signed_pre_key_signature = (
        store.get_identity_key_pair()
        .private_key()
        .calculate_signature(serialized_signed_pre_pub_key)
    )

    # Clients should store their prekeys (both one-time and signed) in the protocol store along
    # with IDs that can be used to retrieve them later.
    pre_key_id = 10
    pre_key_record = state.PreKeyRecord(pre_key_id, pre_key_pair)
    store.save_pre_key(pre_key_id, pre_key_record)

    signed_pre_key_id = 33
    signed_prekey = state.SignedPreKeyRecord(
        signed_pre_key_id,
        42,  # This is a timestamp since the signed prekeys should be periodically rotated
        signed_pre_key_pair,
        signed_pre_key_signature,
    )
    store.save_signed_pre_key(signed_pre_key_id, signed_prekey)
