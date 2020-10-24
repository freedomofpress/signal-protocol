# signal-protocol

WARNING: This is an experimental project and should be used at your own risk. It is using Signal's [`libsignal-protocol-rust`](https://github.com/signalapp/libsignal-protocol-rust) which is still documented as a work in progress.

## Installation

```
pip install signal-protocol
```

## Usage

You can use this as either a library in Python projects, e.g.:

```py
import signal_protocol
```

A standalone CLI is also provided. This package provides the same interface as AsamK's signal-cli project:

```sh
$ signal-cli
```

## Developer Getting Started

You will need both Rust ([how to install Rust](https://rustup.rs/)) and Python 3 installed on your system. To install the project in your virtualenv:

```
python setup.py install
```
