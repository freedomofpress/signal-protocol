from signal_protocol import identity_key


def test_identity_key_pair_init_and_serialization():
    identity_keypair = identity_key.IdentityKeyPair.generate()
    alice_public_serialized = identity_keypair.serialize_public_key()
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
    assert decoded_keypair.serialize_public_key() == test_keypair.serialize_public_key()
    assert decoded_keypair.serialize_private_key() == test_keypair.serialize_private_key()
