from signal_protocol import identity_key


def test_identity_key_pair_init_and_serialization():
    identity_keypair = identity_key.IdentityKeyPair.generate()
    alice_public_serialized = identity_keypair.public_key().serialize()
    alice_identity_key = identity_key.IdentityKey(alice_public_serialized)
    assert alice_public_serialized == alice_identity_key.serialize()


def test_identity_key_pair_generate():
    alice_identity_key = identity_key.IdentityKeyPair.generate()
    assert alice_identity_key.public_key()
    assert alice_identity_key.private_key()


def test_identity_key_pair_from_bytes():
    test_keypair = identity_key.IdentityKeyPair.generate()
    test_keypair_serialized = test_keypair.serialize()

    decoded_keypair = identity_key.IdentityKeyPair(test_keypair_serialized)
    assert decoded_keypair.public_key().serialize() == test_keypair.public_key().serialize()
    assert (
        decoded_keypair.private_key().serialize() == test_keypair.private_key().serialize()
    )
