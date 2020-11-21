from tests.utils.protocol import assert_signal_message_equals, create_signal_message

from signal_protocol import curve, identity_key, protocol


def test_signal_message_serialize_deserialize():
    message = create_signal_message()
    deserialized_message = protocol.SignalMessage.try_from(message.serialized())
    assert_signal_message_equals(message, deserialized_message)


def test_pre_key_signal_message_serialize_deserialize():
    identity_key_pair = curve.KeyPair.generate()
    base_key_pair = curve.KeyPair.generate()

    message = create_signal_message()
    identity_key_pair = identity_key.IdentityKey(
        curve.KeyPair.generate().public_key().serialize()
    )

    pre_key_signal_message = protocol.PreKeySignalMessage(
        3,
        365,
        None,
        97,
        base_key_pair.public_key(),
        identity_key_pair,
        message,
    )

    deserialized_prekey_message = protocol.PreKeySignalMessage.try_from(
        pre_key_signal_message.serialized()
    )

    assert (
        pre_key_signal_message.message_version()
        == deserialized_prekey_message.message_version()
    )
    assert (
        pre_key_signal_message.registration_id()
        == deserialized_prekey_message.registration_id()
    )
    assert (
        pre_key_signal_message.pre_key_id() == deserialized_prekey_message.pre_key_id()
    )
    assert (
        pre_key_signal_message.signed_pre_key_id()
        == deserialized_prekey_message.signed_pre_key_id()
    )
    assert pre_key_signal_message.base_key() == deserialized_prekey_message.base_key()
    assert (
        pre_key_signal_message.identity_key().public_key()
        == deserialized_prekey_message.identity_key().public_key()
    )
    assert_signal_message_equals(
        deserialized_prekey_message.message(), pre_key_signal_message.message()
    )
    assert (
        pre_key_signal_message.serialized() == deserialized_prekey_message.serialized()
    )
