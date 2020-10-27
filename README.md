# signal-protocol

Rust extension providing a Python module for the signal protocol

WARNING: This is an experimental project and should be used at your own risk. It is using Signal's [`libsignal-protocol-rust`](https://github.com/signalapp/libsignal-protocol-rust) which is still documented as a work in progress.

See [here](https://cryptography.io/en/latest/limitations.html) for a fundamental limitation storing secrets in Python-allocated memory.

## Installation

```
pip install signal-protocol
```

Note to build from source, you'll need [Rust](https://rustup.rs/) installed.

## Usage

You can use this as a library in Python projects, e.g.:

```py
import signal_protocol
```

## Developer Getting Started

You will need both [Rust](https://rustup.rs/) and Python 3 installed on your system. To install the project in your virtualenv:

```
python setup.py develop
```

Then run the tests via `pytest -v tests/` to confirm all is working.

To view the docs locally:

```
cargo doc --open
```
