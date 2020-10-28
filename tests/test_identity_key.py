from signal_protocol import identity_key


def test_identity_key_init_and_serialization():
    identity_keypair = identity_key.IdentityKeyPair.generate()
    alice_public = identity_keypair.public_key()
    alice_identity_key = identity_key.IdentityKey(alice_public)
    assert alice_public == alice_identity_key.serialize()


def test_identity_key_generate():
    alice_identity_key = identity_key.IdentityKeyPair.generate()
