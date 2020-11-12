from signal_protocol import address

DEVICE_ID = 1
ALICE_PHONE_NUM = "+14151111111"


def test_basic_address():
    alice_address = address.ProtocolAddress(ALICE_PHONE_NUM, DEVICE_ID)

    assert alice_address.name() == ALICE_PHONE_NUM
    assert alice_address.device_id() == DEVICE_ID


def test_basic_address_str_representation():
    alice_address = address.ProtocolAddress(ALICE_PHONE_NUM, DEVICE_ID)

    assert alice_address.name() in str(alice_address)
    assert str(alice_address.device_id()) in str(alice_address)


def test_basic_address_repr_representation():
    alice_address = address.ProtocolAddress(ALICE_PHONE_NUM, DEVICE_ID)

    assert alice_address.name() in str(alice_address)
    assert str(alice_address.device_id()) in str(alice_address)
