from signal_protocol import curve, address, error, identity_key, protocol, session, session_cipher, state, storage


def run_interaction(alice_store: storage.InMemSignalProtocolStore,
                    alice_address: address.ProtocolAddress,
                    bob_store: storage.InMemSignalProtocolStore,
                    bob_address: address.ProtocolAddress):

    alice_ptext = "It's rabbit season"
    alice_message = session_cipher.message_encrypt(alice_store, bob_address, alice_ptext)

    assert alice_message.message_type() == 2  # CiphertextMessageType::Whisper => 2
    assert session_cipher.message_decrypt(bob_store, alice_address, alice_message).decode('utf8') == alice_ptext

    bob_ptext = "It's duck season"
    bob_message = session_cipher.message_encrypt(bob_store, alice_address, bob_ptext)

    assert bob_message.message_type() == 2  # CiphertextMessageType::Whisper => 2
    assert session_cipher.message_decrypt(alice_store, bob_address, bob_message).decode('utf8') == bob_ptext

    for i in range(10):
        alice_ptext = f"A->B message {i}"
        alice_message = session_cipher.message_encrypt(alice_store, bob_address, alice_ptext)
        assert alice_message.message_type() == 2  # CiphertextMessageType::Whisper => 2
        assert session_cipher.message_decrypt(bob_store, alice_address, alice_message).decode('utf8') == alice_ptext

    for i in range(10):
        bob_ptext = f"B->A message {i}"
        bob_message = session_cipher.message_encrypt(bob_store, alice_address, bob_ptext)
        assert bob_message.message_type() == 2  # CiphertextMessageType::Whisper => 2
        assert session_cipher.message_decrypt(alice_store, bob_address, bob_message).decode('utf8') == bob_ptext

    alice_ooo_messages = []

    for i in range(10):
        alice_ptext = f"A->B OOO message {i}"
        alice_message = session_cipher.message_encrypt(alice_store, bob_address, alice_ptext)
        alice_ooo_messages.append((alice_ptext, alice_message))

    for i in range(10):
        alice_ptext = f"A->B post-OOO message {i}"
        alice_message = session_cipher.message_encrypt(alice_store, bob_address, alice_ptext)
        assert alice_message.message_type() == 2  # CiphertextMessageType::Whisper => 2
        assert session_cipher.message_decrypt(bob_store, alice_address, alice_message).decode('utf8') == alice_ptext

    for i in range(10):
        bob_ptext = f"B->A message post-OOO {i}"
        bob_message = session_cipher.message_encrypt(bob_store, alice_address, bob_ptext)
        assert bob_message.message_type() == 2  # CiphertextMessageType::Whisper => 2
        assert session_cipher.message_decrypt(alice_store, bob_address, bob_message).decode('utf8') == bob_ptext

    ## Now we check that messages can be decrypted when delivered out of order
    for (ptext, ctext) in alice_ooo_messages:
        assert session_cipher.message_decrypt(bob_store, alice_address, ctext).decode('utf8') == ptext
