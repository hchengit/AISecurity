#!/usr/bin/env python3
"""
AISecurity Vault Decryptor — Standalone tool to decrypt .vault files.

This script can decrypt .vault files created by AISecurity without needing
the app installed. You only need the vault passphrase.

Usage:
    python3 vault-decrypt.py <file.vault> [output_file]

If output_file is omitted, the decrypted file is written by removing the
.vault extension (e.g., secret.pdf.vault → secret.pdf).

Requirements:
    pip install cryptography
"""

import sys
import os
import hashlib
import hmac
import struct
from getpass import getpass

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("Error: 'cryptography' package required. Install with:")
    print("  pip install cryptography")
    sys.exit(1)

VAULT_MAGIC = b"AISECVAULT1"
VAULT_SALT_LEN = 32
VAULT_AAD = b"securitycore:vault:v1"
PBKDF2_SALT = b"securitycore:pbkdf2:v1:salt"
PBKDF2_ITERATIONS = 100_000


def derive_key(passphrase: str) -> bytes:
    """Derive AES-256 key from passphrase using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=PBKDF2_SALT,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def decrypt_vault_file(vault_path: str, passphrase: str) -> bytes:
    """Decrypt a .vault file and return the plaintext bytes."""
    with open(vault_path, "rb") as f:
        data = f.read()

    header_len = len(VAULT_MAGIC) + VAULT_SALT_LEN

    if len(data) > header_len and data[:len(VAULT_MAGIC)] == VAULT_MAGIC:
        # Portable format: AISECVAULT1 || salt (32) || nonce (12) || ciphertext
        salt = data[len(VAULT_MAGIC):header_len]
        enc_data = data[header_len:]
    else:
        # Legacy format: nonce (12) || ciphertext (no salt embedded)
        print("Warning: Legacy vault format detected (no embedded salt).")
        print("You'll need the vault salt file (~/.mac-security/.vault-salt).")
        salt_path = os.path.expanduser("~/.mac-security/.vault-salt")
        if not os.path.exists(salt_path):
            print(f"Error: Salt file not found at {salt_path}")
            sys.exit(1)
        with open(salt_path, "rb") as sf:
            salt = sf.read()
        enc_data = data

    if len(enc_data) < 12 + 16:
        raise ValueError("Encrypted data too short (need nonce + GCM tag)")

    nonce = enc_data[:12]
    ciphertext = enc_data[12:]

    # Key derivation: PBKDF2(passphrase + hex(salt))
    salt_hex = salt.hex()
    salted_passphrase = passphrase + salt_hex
    key = derive_key(salted_passphrase)

    # Decrypt with AES-256-GCM
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, VAULT_AAD)
    except Exception:
        raise ValueError("Decryption failed — wrong passphrase or corrupted file")

    return plaintext


def main():
    if len(sys.argv) < 2:
        print("AISecurity Vault Decryptor")
        print()
        print("Usage: python3 vault-decrypt.py <file.vault> [output_file]")
        print()
        print("Decrypts .vault files created by AISecurity.")
        print("You need the vault passphrase that was set during vault setup.")
        sys.exit(0)

    vault_path = sys.argv[1]
    if not os.path.exists(vault_path):
        print(f"Error: File not found: {vault_path}")
        sys.exit(1)

    if not vault_path.endswith(".vault"):
        print(f"Warning: File doesn't have .vault extension: {vault_path}")

    # Determine output path
    if len(sys.argv) >= 3:
        output_path = sys.argv[2]
    elif vault_path.endswith(".vault"):
        output_path = vault_path[:-6]  # Remove .vault extension
    else:
        output_path = vault_path + ".decrypted"

    if os.path.exists(output_path):
        confirm = input(f"Output file exists: {output_path}\nOverwrite? [y/N] ")
        if confirm.lower() != "y":
            print("Aborted.")
            sys.exit(0)

    passphrase = getpass("Vault passphrase: ")
    if not passphrase:
        print("Error: Passphrase cannot be empty.")
        sys.exit(1)

    try:
        plaintext = decrypt_vault_file(vault_path, passphrase)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"Decrypted: {vault_path} → {output_path} ({len(plaintext)} bytes)")


if __name__ == "__main__":
    main()
