# signal-protocol

[![CircleCI](https://circleci.com/gh/freedomofpress/signal-protocol.svg?style=svg)](https://circleci.com/gh/freedomofpress/signal-protocol)
[![PyPI version](https://badge.fury.io/py/signal-protocol.svg)](https://badge.fury.io/py/signal-protocol)

Experimental Python bindings to [`libsignal-client`](https://github.com/signalapp/libsignal-client) Rust signal protocol implementation. This project provides a Rust extension using [PyO3](https://pyo3.rs/) to define a `signal_protocol` Python module. See [here](https://cryptography.io/en/latest/limitations.html) for a fundamental limitation storing secrets in Python-allocated memory. ⚠️USE AT YOUR OWN RISK!⚠️

# Installation

To use the wheel distributions you do not need the Rust toolchain installed:

```
pip install signal-protocol
```

# Usage

## Initial setup

```py
from signal_protocol import curve, identity_key, state, storage

# Each client must generate a long-term identity key pair.
# This should be stored somewhere safe and persistent.
identity_key_pair = identity_key.IdentityKeyPair.generate()

# Clients must generate prekeys. The example here is generating a
# single prekey, but clients will generate many as they are one-time use
# and consumed when a message from a new chat participant is sent. See issue #7.
pre_key_pair = curve.KeyPair.generate()

# Clients must generate a registration_id and store it somewhere safe and persistent.
registration_id = 12  # TODO generate (not yet supported in upstream crate)

# The InMemSignalProtocolStore is a single object which provide the four storage
# interfaces required: IdentityKeyStore (for one's own identity key state and the (public)
# identity keys for other chat participants), PreKeyStore (for one's own prekey state),
# SignedPreKeyStore (for one's own signed prekeys), and SessionStore (for established sessions
# with chat participants).
store = storage.InMemSignalProtocolStore(identity_key_pair, registration_id)

# Clients should also generate a signed prekey.
signed_pre_key_pair = curve.KeyPair.generate()
serialized_signed_pre_pub_key = signed_pre_key_pair.public_key().serialize()
signed_pre_key_signature = store.get_identity_key_pair().private_key().calculate_signature(serialized_signed_pre_pub_key)

# Clients should store their prekeys (both one-time and signed) in the protocol store
# along with IDs that can be used to retrieve them later.
pre_key_id = 10
pre_key_record = state.PreKeyRecord(pre_key_id, pre_key_pair)
store.save_pre_key(pre_key_id, pre_key_record)

signed_pre_key_id = 33
signed_prekey = state.SignedPreKeyRecord(
            signed_pre_key_id,
            42, # This is a timestamp since this key should be periodically rotated
            signed_pre_key_pair,
            signed_pre_key_signature,
        )
store.save_signed_pre_key(signed_pre_key_id, signed_prekey)
```

## Sending a message to a new participant

```py
from signal_protocol import session, session_cipher

# To create a session, you must fetch a prekey bundle for the recipient from the server
# Here the prekey bundle is `recipient_bundle` for participant `recipient_address`
session.process_prekey_bundle(
    recipient_address,
    store,
    recipient_bundle,
)

# Once the prekey bundle is processed (storing data from the recipient in your local
# protocol store), you can encrypt messages
ciphertext = session_cipher.message_encrypt(store, recipient_address, "hello")
```

# Developer Getting Started

You will need both [Rust](https://rustup.rs/) and Python 3.7+ installed on your system. To install the project in your virtualenv:

```
pip install -r requirements.txt
python setup.py develop  # This will call out to rustc
```

Then run the tests via `pytest -v tests/` to confirm all is working. Tests are ported to Python from the upstream crate. You can use the tests as a reference for how to use the library.
