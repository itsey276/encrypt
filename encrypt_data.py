#!/usr/bin/env python3
"""Encrypt or decrypt files under ./data with password-derived AES-256-GCM.

Encrypted files are written next to their originals with a .enc suffix. Originals
are never removed or overwritten. Requires: python -m pip install cryptography
"""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import stat
import sys
import tempfile
from pathlib import Path

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as error:
    raise SystemExit("Missing dependency: install it with 'python -m pip install cryptography'.") from error

MAGIC = b"PYENC1\r\n"
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024
KEY_SIZE = 32  # 256-bit AES key


def derive_key(password: bytes, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=KEY_SIZE, n=2**15, r=8, p=1).derive(password)


def make_temp(destination: Path) -> tuple[int, Path]:
    fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
    return fd, Path(name)


def publish_without_overwrite(temp_path: Path, destination: Path) -> None:
    # A hard link publishes atomically and fails rather than replacing an existing file.
    os.link(temp_path, destination)
    temp_path.unlink()


def encrypt_file(source: Path, password: bytes) -> None:
    destination = source.with_name(source.name + ".enc")
    if destination.exists():
        raise FileExistsError(f"output already exists: {destination}")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    header = MAGIC + salt + nonce
    encryptor = Cipher(algorithms.AES(derive_key(password, salt)), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)

    fd, temp_path = make_temp(destination)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_file:
            output.write(header)
            while chunk := input_file.read(CHUNK_SIZE):
                output.write(encryptor.update(chunk))
            output.write(encryptor.finalize())
            output.write(encryptor.tag)
            output.flush()
            os.fsync(output.fileno())
        publish_without_overwrite(temp_path, destination)
    finally:
        temp_path.unlink(missing_ok=True)


def decrypt_file(source: Path, password: bytes) -> None:
    if source.suffix != ".enc":
        raise ValueError("encrypted files must have a .enc suffix")
    destination = source.with_suffix("")
    if destination.exists():
        raise FileExistsError(f"output already exists: {destination}")

    fd, temp_path = make_temp(destination)
    try:
        with source.open("rb") as input_file:
            header = input_file.read(len(MAGIC) + SALT_SIZE + NONCE_SIZE)
            if len(header) != len(MAGIC) + SALT_SIZE + NONCE_SIZE or not header.startswith(MAGIC):
                raise ValueError("not a supported encrypted file")
            salt = header[len(MAGIC):len(MAGIC) + SALT_SIZE]
            nonce = header[-NONCE_SIZE:]
            decryptor = Cipher(
                algorithms.AES(derive_key(password, salt)), modes.GCM(nonce)
            ).decryptor()
            decryptor.authenticate_additional_data(header)

            with os.fdopen(fd, "wb") as output:
                tail = b""
                while chunk := input_file.read(CHUNK_SIZE):
                    buffered = tail + chunk
                    if len(buffered) <= TAG_SIZE:
                        tail = buffered
                        continue
                    ciphertext, tail = buffered[:-TAG_SIZE], buffered[-TAG_SIZE:]
                    output.write(decryptor.update(ciphertext))
                if len(tail) != TAG_SIZE:
                    raise ValueError("encrypted file is truncated")
                output.write(decryptor.finalize_with_tag(tail))  # verifies authenticity
                output.flush()
                os.fsync(output.fileno())
        publish_without_overwrite(temp_path, destination)
    finally:
        temp_path.unlink(missing_ok=True)


def files_under(root: Path, decrypting: bool) -> list[Path]:
    result: list[Path] = []
    for current, directories, filenames in os.walk(root, followlinks=False):
        base = Path(current)
        directories[:] = [name for name in directories if not (base / name).is_symlink()]
        for name in filenames:
            path = base / name
            try:
                mode = path.lstat().st_mode
            except OSError:
                continue
            if not stat.S_ISREG(mode):  # do not follow or process symlinks/devices
                continue
            if decrypting:
                if path.suffix == ".enc":
                    result.append(path)
            elif path.suffix != ".enc":
                result.append(path)
    return sorted(result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("encrypt", "decrypt"), help="encrypt files, or decrypt .enc files")
    args = parser.parse_args()

    root = (Path.cwd() / "data").resolve()
    if not root.is_dir():
        parser.error(f"data directory does not exist: {root}")

    password = getpass.getpass("Password: ")
    if not password:
        parser.error("password must not be empty")
    if args.action == "encrypt":
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            parser.error("passwords do not match")

    candidates = files_under(root, decrypting=args.action == "decrypt")
    if not candidates:
        print("No matching files found.")
        return 0

    failures = 0
    for path in candidates:
        try:
            if args.action == "encrypt":
                encrypt_file(path, password.encode("utf-8"))
                print(f"Encrypted: {path}")
            else:
                decrypt_file(path, password.encode("utf-8"))
                print(f"Decrypted: {path}")
        except (OSError, ValueError, InvalidTag) as error:
            failures += 1
            print(f"Failed: {path}: {error}", file=sys.stderr)

    if failures:
        print(f"Completed with {failures} failure(s); originals were retained.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
