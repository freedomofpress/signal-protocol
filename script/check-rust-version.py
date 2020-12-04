# Script to check that version of Rust in local toolchain and build scripts
# matches upstream Signal library version.

import urllib.request, urllib.error
import subprocess
import sys

from typing import Optional, Tuple

FILES = [
    "build-wheels.sh",
    ".circleci/config.yml",
]

UPSTREAM_TOOLCHAIN_FILE_URL = (
    "https://raw.githubusercontent.com/signalapp/libsignal-client/master/rust-toolchain"
)

# get local git directory
git_dir = (
    subprocess.Popen(["git", "rev-parse", "--show-toplevel"], stdout=subprocess.PIPE)
    .communicate()[0]
    .rstrip()
    .decode("utf-8")
)


def get_versions() -> Tuple[str, str]:
    # get our local nightly version
    try:
        with open(git_dir + "/rust-toolchain") as f:
            our_version = f.read().strip()
    except:
        print("Our rust-toolchain file has moved or disappeared!")
        sys.exit(1)

    # get upstream nightly version
    try:
        with urllib.request.urlopen(UPSTREAM_TOOLCHAIN_FILE_URL) as response:
            upstream_version = response.read().decode("utf-8").strip()
    except urllib.error.HTTPError:
        print("Upstream toolchain file has moved or disappeared!")
        sys.exit(1)
    except:
        print("Problem with request")
        sys.exit(1)

    return our_version, upstream_version


def check_toolchain_files(our_version: str, upstream_version: str) -> Optional[bool]:
    if our_version == upstream_version:
        print("rust-toolchain files match ✓")
        return True
    else:
        print("rust-toolchain files do not match ✗")
        sys.exit(1)


def check_file(filename: str, upstream_version: str) -> Optional[bool]:
    with open(git_dir + "/" + filename, "r") as f:

        rustupLines = []

        for line in f:
            line = line.strip()
            if "rustup" in line:
                rustupLines.append(line)

        for line in rustupLines:
            if upstream_version in line:
                continue
            else:
                print("{} contains incorrect Rust version ✗".format(filename))
                print("found a bad line in {}: ".format(filename) + line.strip())
                sys.exit(1)

        print("{} uses correct upstream Rust version ✓".format(filename))
        return True


if __name__ == "__main__":

    our_version, upstream_version = get_versions()

    print("\nRust versions defined in rust-toolchain files:")
    print("upstream: " + upstream_version)
    print("ours:     " + our_version)
    print()

    check_toolchain_files(our_version, upstream_version)

    for f in FILES:
        check_file(f, upstream_version)

    print()
    print("🎉 Rust version synced with upstream Signal library!")
