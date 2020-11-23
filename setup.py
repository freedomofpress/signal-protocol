#!/usr/bin/env python

import sys
from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="signal-protocol",
    version="0.2.0",
    classifiers=[
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Rust",
    ],
    rust_extensions=[RustExtension("signal_protocol", "Cargo.toml", binding=Binding.PyO3)],
    setup_requires=["setuptools-rust>=0.10.1", "wheel"],
    zip_safe=False,  # Rust extensions are not zip safe
)
