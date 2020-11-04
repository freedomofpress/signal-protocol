from signal_protocol import curve, address, identity_key, protocol, session, session_cipher, state, storage

DEVICE_ID = 1


def test_basic_prekey_v3():
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
        pre_key_id,
        bob_pre_key_pair.public_key(),
        signed_pre_key_id,
        bob_signed_pre_key_pair.public_key(),
        bob_signed_pre_key_signature,
        bob_store.get_identity_key_pair().identity_key(),
    )

    assert alice_store.load_session(bob_address) is None

    session.process_prekey_bundle(
        bob_address,
        alice_store,
        bob_pre_key_bundle,
    )

    assert alice_store.load_session(bob_address)
    assert alice_store.load_session(bob_address).session_version() == 3

    original_message = "Hobgoblins hold themselves to high standards of military honor"

    outgoing_message = session_cipher.encrypt(alice_store, bob_address, original_message)
    outgoing_message.message_type() == 3  # 3 means PreKey
    outgoing_message_wire = outgoing_message.serialize()

    # Now over to fake Bob for processing the first message

    incoming_message = protocol.PreKeySignalMessage.try_from(outgoing_message_wire)

    bob_prekey = state.PreKeyRecord(pre_key_id, bob_pre_key_pair)
    bob_store.save_pre_key(pre_key_id, bob_prekey)

    signed_prekey = state.SignedPreKeyRecord(
            signed_pre_key_id,
            42,
            bob_signed_pre_key_pair,
            bob_signed_pre_key_signature,
        )

    bob_store.save_signed_pre_key(signed_pre_key_id, signed_prekey)

#     let ptext = decrypt(&mut bob_store, &alice_address, &incoming_message)?;

#     assert_eq!(String::from_utf8(ptext).unwrap(), original_message);

#     let bobs_response = "Who watches the watchers?";

#     assert!(bob_store.load_session(&alice_address, None)?.is_some());
#     let bobs_session_with_alice = bob_store.load_session(&alice_address, None)?.unwrap();
#     assert_eq!(
#         bobs_session_with_alice.session_state()?.session_version()?,
#         3
#     );
#     assert_eq!(
#         bobs_session_with_alice
#             .session_state()?
#             .alice_base_key()?
#             .len(),
#         32 + 1
#     );

#     let bob_outgoing = encrypt(&mut bob_store, &alice_address, bobs_response)?;

#     assert_eq!(bob_outgoing.message_type(), CiphertextMessageType::Whisper);

#     let alice_decrypts = decrypt(&mut alice_store, &bob_address, &bob_outgoing)?;

#     assert_eq!(String::from_utf8(alice_decrypts).unwrap(), bobs_response);

#     run_interaction(
#         &mut alice_store,
#         &alice_address,
#         &mut bob_store,
#         &bob_address,
#     )?;

#     let mut alice_store = support::test_in_memory_protocol_store();

#     let bob_pre_key_pair = KeyPair::generate(&mut csprng);
#     let bob_signed_pre_key_pair = KeyPair::generate(&mut csprng);

#     let bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key.serialize();
#     let bob_signed_pre_key_signature = bob_store
#         .get_identity_key_pair(None)?
#         .private_key()
#         .calculate_signature(&bob_signed_pre_key_public, &mut csprng)?;

#     let pre_key_id = 31337;
#     let signed_pre_key_id = 22;

#     let bob_pre_key_bundle = PreKeyBundle::new(
#         bob_store.get_local_registration_id(None)?,
#         1, // device id
#         Some(pre_key_id + 1),
#         Some(bob_pre_key_pair.public_key), // pre key
#         signed_pre_key_id + 1,
#         bob_signed_pre_key_pair.public_key,
#         bob_signed_pre_key_signature.to_vec(),
#         *bob_store.get_identity_key_pair(None)?.identity_key(),
#     )?;

#     bob_store.save_pre_key(
#         pre_key_id + 1,
#         &PreKeyRecord::new(pre_key_id + 1, &bob_pre_key_pair),
#         None,
#     )?;
#     bob_store.save_signed_pre_key(
#         signed_pre_key_id + 1,
#         &SignedPreKeyRecord::new(
#             signed_pre_key_id + 1,
#             /*timestamp*/ 42,
#             &bob_signed_pre_key_pair,
#             &bob_signed_pre_key_signature,
#         ),
#         None,
#     )?;

#     process_prekey_bundle(
#         &bob_address,
#         &mut alice_store.session_store,
#         &mut alice_store.identity_store,
#         &bob_pre_key_bundle,
#         &mut csprng,
#         None,
#     )?;

#     let outgoing_message = encrypt(&mut alice_store, &bob_address, original_message)?;

#     assert_eq!(
#         decrypt(&mut bob_store, &alice_address, &outgoing_message).unwrap_err(),
#         SignalProtocolError::UntrustedIdentity(alice_address.clone())
#     );

#     assert_eq!(
#         bob_store.save_identity(
#             &alice_address,
#             alice_store.get_identity_key_pair(None)?.identity_key(),
#             None,
#         )?,
#         true
#     );

#     let decrypted = decrypt(&mut bob_store, &alice_address, &outgoing_message)?;
#     assert_eq!(String::from_utf8(decrypted).unwrap(), original_message);

#     // Sign pre-key with wrong key:
#     let bob_pre_key_bundle = PreKeyBundle::new(
#         bob_store.get_local_registration_id(None)?,
#         1, // device id
#         Some(pre_key_id),
#         Some(bob_pre_key_pair.public_key), // pre key
#         signed_pre_key_id,
#         bob_signed_pre_key_pair.public_key,
#         bob_signed_pre_key_signature.to_vec(),
#         *alice_store.get_identity_key_pair(None)?.identity_key(),
#     )?;

#     assert!(process_prekey_bundle(
#         &bob_address,
#         &mut alice_store.session_store,
#         &mut alice_store.identity_store,
#         &bob_pre_key_bundle,
#         &mut csprng,
#         None,
#     )
#     .is_err());

#     Ok(())