import signal_protocol


def test_curve_key_generation():
    _ = signal_protocol.curve.KeyPair.generate()
