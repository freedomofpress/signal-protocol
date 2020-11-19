from signal_protocol import identity_key, fingerprint


def test_fingerprint_equality():
    version = 2
    iterations = 5200
    alice_stable_id = b"+14152222222"
    bob_stable_id = b"+14153333333"
    alice_key = identity_key.IdentityKeyPair.generate().identity_key()
    bob_key = identity_key.IdentityKeyPair.generate().identity_key()

    alice_fingerprint = fingerprint.Fingerprint(
        version,
        iterations,
        alice_stable_id,
        alice_key,
        bob_stable_id,
        bob_key,
    )
    bob_fingerprint = fingerprint.Fingerprint(
        version,
        iterations,
        bob_stable_id,
        bob_key,
        alice_stable_id,
        alice_key,
    )
    assert str(alice_fingerprint) == str(bob_fingerprint)

    eve_stable_id = b"+14153333666"
    eve_key = identity_key.IdentityKeyPair.generate().identity_key()
    eve_fingerprint = fingerprint.Fingerprint(
        version,
        iterations,
        eve_stable_id,
        eve_key,
        alice_stable_id,
        alice_key,
    )
    assert str(alice_fingerprint) != str(eve_fingerprint)
