from signal_protocol import curve
from signal_protocol import address

DEVICE_ID = 1


def test_basic_prekey_v3():
    """Ported to Python from upstream crate"""
    alice_address = address.ProtocolAddress("+14151111111", DEVICE_ID)
    bob_address = address.ProtocolAddress("+14151111112", DEVICE_ID)

    alice_pre_pub, alice_pre_priv = curve.generate_keypair()
    bob_pre_pub, bob_pre_priv = curve.generate_keypair()

