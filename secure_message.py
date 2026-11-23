"""
Secure message demo (single machine, no network).

User A (sender) -> User B (receiver)

SENDER (User A):
  1. Type a message
  2. Generate a random AES-256 key and encrypt the message (AES-GCM)
  3. Encrypt the AES key with User B's PUBLIC key (RSA-OAEP)
  4. Hash the message (SHA-256)
  5. Sign the hash with User A's PRIVATE key (RSA-PSS)

RECEIVER (User B):
  1. Decrypt the AES key with User B's PRIVATE key
  2. Decrypt the message with the AES key
  3. Hash the decrypted message (SHA-256)
  4. Verify the signature with User A's PUBLIC key

Requires:  pip install cryptography
Run:       python secure_message.py
"""

import os
import base64
import hashlib
import socket
from getpass import getpass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag


# ---------- helpers ----------
def b64(data: bytes) -> str:
    """Show bytes as readable base64 text (shortened if long)."""
    s = base64.b64encode(data).decode()
    return s if len(s) <= 60 else s[:60] + "..."


OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)
PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)
def canonical_record(
    name: str,
    record_type: str,
    address: str,
    key_id: str,
    inception: int,
    expiration: int,
    transaction_id: str,
    nonce: str,
) -> bytes:
    fields = [
        name.rstrip(".").lower(),
        record_type.upper(),
        address,
        key_id,
        str(inception),
        str(expiration),
        transaction_id,
        nonce,
    ]

    if any(not field or "|" in field for field in fields):
        raise ValueError("Canonical record fields must be non-empty and cannot contain '|'")

    return "|".join(fields).encode("utf-8")

DNS_RECORDS = {
    ("www.example.com", "A"): "192.168.1.10",
    ("mail.example.com", "A"): "192.168.1.20",
}


# ---------- key setup ----------
def generate_keypair(name: str, password: bytes):
    """Create an RSA key pair, save it to PEM files, return (private, public)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(f"{name}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        ))
    with open(f"{name}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print(f"  Created {name}_private.pem and {name}_public.pem")
    return private_key, public_key

def load_or_create_server_keys():
    private_path = Path("server_private.pem")
    public_path = Path("server_public.pem")

    if private_path.exists() != public_path.exists():
        raise FileNotFoundError(
            "Expected both server key files, or neither. Restore or remove the remaining file."
        )

    password = getpass("Server private-key password: ").encode("utf-8")

    if not private_path.exists():
        return generate_keypair("server", password)

    with private_path.open("rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=password
        )

    with public_path.open("rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return private_key, public_key


# ---------- sender (User A) ----------
def sender_encrypt_and_sign(message: str, receiver_public_key, sender_private_key):
    print("\n========== SENDER (User A) ==========")
    data = message.encode("utf-8")

    # 1. AES key + encrypt message
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, data, None)
    print(f"[1] AES-256 key generated : {b64(aes_key)}")
    print(f"[2] Encrypted message     : {b64(ciphertext)}")

    # 2. Encrypt AES key with receiver's public key
    encrypted_aes_key = receiver_public_key.encrypt(aes_key, OAEP)
    print(f"[3] AES key encrypted with User B's public key: {b64(encrypted_aes_key)}")

    # 3. Hash the message
    digest = hashlib.sha256(data).digest()
    print(f"[4] SHA-256 hash of message: {digest.hex()}")

    # 4. Sign the hash with sender's private key
    signature = sender_private_key.sign(
        digest, PSS, utils.Prehashed(hashes.SHA256())
    )
    print(f"[5] Signature (User A's private key): {b64(signature)}")

    # This bundle is what would be "sent" to User B
    return {
        "encrypted_aes_key": encrypted_aes_key,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "signature": signature,
    }


# ---------- receiver (User B) ----------
def receiver_decrypt_and_verify(package, receiver_private_key, sender_public_key):
    print("\n========== RECEIVER (User B) ==========")

    # 1. Recover AES key with receiver's private key
    try:
        aes_key = receiver_private_key.decrypt(package["encrypted_aes_key"], OAEP)
    except ValueError:
        print("[X] Could not decrypt the AES key (wrong key or corrupted).")
        return None
    print(f"[1] AES key recovered with User B's private key: {b64(aes_key)}")

    # 2. Decrypt the message (GCM also checks it wasn't modified)
    try:
        data = AESGCM(aes_key).decrypt(package["nonce"], package["ciphertext"], None)
    except InvalidTag:
        print("[X] Decryption failed: ciphertext was tampered with.")
        return None
    message = data.decode("utf-8")
    print(f"[2] Decrypted message: {message}")

    # 3. Hash the decrypted message
    digest = hashlib.sha256(data).digest()
    print(f"[3] SHA-256 hash of decrypted message: {digest.hex()}")

    # 4. Verify signature with sender's public key
    try:
        sender_public_key.verify(
            package["signature"], digest, PSS, utils.Prehashed(hashes.SHA256())
        )
        print("[4] Signature VALID: message is from User A and unchanged.")
    except InvalidSignature:
        print("[X] Signature INVALID: not from User A, or message was altered.")
        return None

    return message


# ---------- tamper tests ----------
def tamper_tests(package, server_private, user_public, attacker_private):
    print("\n========== TAMPER TESTS ==========")

    print("\n--- Test 1: attacker flips one bit of the ciphertext ---")
    bad = dict(package)
    ct = bytearray(bad["ciphertext"])
    ct[0] ^= 1
    bad["ciphertext"] = bytes(ct)
    receiver_decrypt_and_verify(bad, server_private, user_public)

    print("\n--- Test 2: attacker (User C) re-signs it with their own key ---")
    aes_key = server_private.decrypt(package["encrypted_aes_key"], OAEP)
    data = AESGCM(aes_key).decrypt(package["nonce"], package["ciphertext"], None)
    fake = dict(package)
    fake["signature"] = attacker_private.sign(
        hashlib.sha256(data).digest(), PSS, utils.Prehashed(hashes.SHA256())
    )
    receiver_decrypt_and_verify(fake, server_private, user_public)






def run_server(server, server_private, server_public):
    server.listen(5)
    while True:
        connection, address = server.accept()
        with connection:
            data = connection.recv(4096)
            if not data:
                continue

            response = handle_request(data, server_private, server_public)
            connection.sendall(response)


def handle_request(data, server_private, server_public):
    address = DNS_RECORDS.get((name.lower(), record_type.upper()))
    if address is None:
        print("Error ")
    return

    


# ---------- main ----------
def main():
    # Creates keys in a file, loads them if files exist
    server_private, server_public = load_or_create_server_keys()

    record_bytes = canonical_record(
        "www.example.com",
        "A",
        "192.168.1.10",
        "example-key-id",
        1_700_000_000,
        1_800_000_000,
        "tx-001",
        "0123456789abcdef"
    )

    # Sign signature and verify
    signature = server_private.sign(record_bytes, PSS, hashes.SHA256())
    server_public.verify(signature, record_bytes, PSS, hashes.SHA256())
    print("Valid Sig before tampering")
    
    # Tamper signature and verify
    altered_record = record_bytes.replace(
    b"192.168.1.10",
    b"192.168.1.99",
    )
    print("Tampering signature...")
    try:
        server_public.verify(signature, altered_record, PSS, hashes.SHA256())
    except InvalidSignature:
        print("Tampering successfully rejected")
    else:
        raise AssertionError("Changed record unexpectedly passed verification")



    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 5300))
        run_server(server, server_private, server_public)





if __name__ == "__main__":
    main()
