# signal-protocol

Experimental Python bindings to Signal's [`libsignal-protocol-rust`](https://github.com/signalapp/libsignal-protocol-rust). This project provides a Rust extension using [PyO3](https://pyo3.rs/) to define a `signal_protocol` Python module. See [here](https://cryptography.io/en/latest/limitations.html) for a fundamental limitation storing secrets in Python-allocated memory. ⚠️USE AT YOUR OWN RISK!⚠️

## Installation

```
pip install signal-protocol
```

If you want to build from source, you'll need [Rust](https://rustup.rs/) installed.

## Usage

Generating a long-term identity key, a registration ID, and prekeys:

```py
import signal_protocol
```

## Developer Getting Started

You will need both [Rust](https://rustup.rs/) and Python 3 installed on your system. To install the project in your virtualenv:

```
pip install -r requirements.txt
python setup.py develop  # This will call out to rustc
```

Then run the tests via `pytest -v tests/` to confirm all is working.

To view the docs locally:

```
cargo doc --open
```
