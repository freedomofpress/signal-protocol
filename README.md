# signal-protocol

Experimental Python bindings to Signal's [`libsignal-protocol-rust`](https://github.com/signalapp/libsignal-protocol-rust) Rust crate. This project provides a Rust extension using [PyO3](https://pyo3.rs/) to define a `signal_protocol` Python module. See [here](https://cryptography.io/en/latest/limitations.html) for a fundamental limitation storing secrets in Python-allocated memory. ⚠️USE AT YOUR OWN RISK!⚠️

## Usage

Generating a long-term identity key and a single prekey:

```py
from signal_protocol import curve, identity_key

identity_key_pair = identity_key.IdentityKeyPair.generate()
pre_key_pair = curve.KeyPair.generate()
```

See in particular `tests/test_session.py` for a simulated session between two parties Alice and Bob.

## Developer Getting Started

You will need both [Rust](https://rustup.rs/) and Python 3 installed on your system. To install the project in your virtualenv:

```
pip install -r requirements.txt
python setup.py develop  # This will call out to rustc
```

Then run the tests via `pytest -v tests/` to confirm all is working. You can use the tests as a reference for how to use the library.
