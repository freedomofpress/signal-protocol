import signal_protocol


def test_curve_key_generation():
    _ = signal_protocol.curve.KeyPair.generate()


def test_curve_signature_and_verify():
    keypair = signal_protocol.curve.KeyPair.generate()

    message = b"The serpent creatures known as yuan-ti"
    sig = keypair.private_key().calculate_signature(message)

    assert signal_protocol.curve.verify_signature(keypair.public_key(), message, sig)
