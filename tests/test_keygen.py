from signal_protocol import curve


def test_basic_prekey_v3():
    alice_pre_pub, alice_pre_priv = curve.generate_keypair()
    bob_pre_pub, bob_pre_priv = curve.generate_keypair()
