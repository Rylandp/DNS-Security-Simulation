import base64
import hashlib
import socket
from getpass import getpass
from pathlib import Path
import json
import time
import sys

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


# ---------- helpers ----------
def public_key_der(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def key_fingerprint(public_key) -> str:
    """Return the SHA-256 fingerprint used as the key identifier."""
    return hashlib.sha256(public_key_der(public_key)).hexdigest()

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
    ttl: int,
) -> bytes:
    fields = [
        name.rstrip(".").lower(),
        record_type.upper(),
        address,
        str(ttl),
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



def run_server(server, server_private, server_public):
    server.listen(5)
    server.settimeout(1.0)
    try:
        while True:
            try:
                connection, address = server.accept()
            except socket.timeout:
                continue
            with connection:
                data = connection.recv(4096)
                if not data:
                    continue

                response = handle_request(data, server_private, server_public)
                connection.sendall(response)
    except KeyboardInterrupt:
        print("\nServer stopped.")
        sys.exit()

def run_client(host, port, name, record_type):
    # client query 
    dns_query = {
    "type": "DNS_QUERY",
    "transaction_id": "tx-001",
    "name": name,
    "record_type": record_type,
    "nonce": "123abc",
    }
    
    query_bytes = json.dumps(dns_query).encode("utf-8")
    with socket.create_connection((host, port)) as client:
        client.sendall(query_bytes)
        response_bytes = client.recv(4096)

    response = json.loads(response_bytes.decode("utf-8"))
    print(response)

def handle_request(data, server_private, server_public):
    query = json.loads(data.decode("utf-8"))
    name = query.get("name", "").rstrip(".").lower()
    record_type = query.get("record_type", "").upper()
    address = DNS_RECORDS.get((name, record_type))
    if address is None:
        errResponse = {
                "type": "DNS_RESPONSE",
                "status": "FAILURE",
                "name": name,
                "record_type": record_type,
                "address": address,
                "error": f"No {record_type} record found for {name}."
            }
        print(f"Error: Record type {record_type} is not available for {name}")
        return json.dumps(errResponse).encode("utf-8")

    ttl = 60
    inception = int(time.time())
    key_id = key_fingerprint(server_public)
    nonce = query.get("nonce")
    transaction_id = query.get("transaction_id")
    expiration = inception + ttl
    
    server_public_pem = server_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

    record = canonical_record(
                name,
                record_type,
                address,
                key_id,
                inception,
                expiration,
                transaction_id,
                nonce,
                ttl,
            ) 
    
    
    signature = server_private.sign(
                record,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
    
    response = {
                "type": "DNS_RESPONSE",
                "status": "SUCCESS",
                "transaction_id": transaction_id,
                "nonce": nonce,
                "name": name,
                "record_type": record_type,
                "address": address,
                "ttl": ttl,
                "key_id": key_id,
                "public_key": base64.b64encode(server_public_pem).decode("ascii"),
                "inception": inception,
                "expiration": expiration,
                "signature": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(response).encode("utf-8")

    


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
        "0123456789abcdef",
        60
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
