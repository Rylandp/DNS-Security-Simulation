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
def tamper_tests(package, b_private, a_public, c_private):
    print("\n========== TAMPER TESTS ==========")

    print("\n--- Test 1: attacker flips one bit of the ciphertext ---")
    bad = dict(package)
    ct = bytearray(bad["ciphertext"])
    ct[0] ^= 1
    bad["ciphertext"] = bytes(ct)
    receiver_decrypt_and_verify(bad, b_private, a_public)

    print("\n--- Test 2: attacker (User C) re-signs it with their own key ---")
    aes_key = b_private.decrypt(package["encrypted_aes_key"], OAEP)
    data = AESGCM(aes_key).decrypt(package["nonce"], package["ciphertext"], None)
    fake = dict(package)
    fake["signature"] = c_private.sign(
        hashlib.sha256(data).digest(), PSS, utils.Prehashed(hashes.SHA256())
    )
    receiver_decrypt_and_verify(fake, b_private, a_public)


# ---------- main ----------
def main():
    print("Generating keys...")
    a_private, a_public = generate_keypair("userA", b"passwordA")
    b_private, b_public = generate_keypair("userB", b"passwordB")
    c_private, _ = generate_keypair("userC_attacker", b"passwordC")

    message = input("\nEnter a message to send from User A to User B: ")

    package = sender_encrypt_and_sign(message, b_public, a_private)
    result = receiver_decrypt_and_verify(package, b_private, a_public)

    if result is not None:
        print(f"\nSUCCESS. User B received: \"{result}\"")
        print(f"Matches original: {result == message}")

    if input("\nRun tamper tests? (y/n): ").strip().lower() == "y":
        tamper_tests(package, b_private, a_public, c_private)


if __name__ == "__main__":
    main()
