from signal_protocol import curve, address, identity_key, state, storage

DEVICE_ID = 1

def test_define_prekey_bundle_under_prekey_exhaustion():
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
        None,
        None,
        signed_pre_key_id,
        bob_signed_pre_key_pair.public_key(),
        bob_signed_pre_key_signature,
        bob_store.get_identity_key_pair().identity_key(),
    )
