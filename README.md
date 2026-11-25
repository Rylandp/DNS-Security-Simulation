## Requirements

- Python 3
- The `cryptography` Python package

Install the dependency from PowerShell in the project directory:

```powershell
python -m pip install -r requirements.txt
```

## Start the server

Open a PowerShell terminal in this project folder and run:

```powershell
python secure_message.py
```

On the first run, enter a password when prompted. The program creates
`server_private.pem` and `server_public.pem` in the project folder. On later
runs, enter the same password to load the private key. Keep the private key
and password secret.

The server listens on `127.0.0.1`, port `5300`. Leave this terminal running.
Press Ctrl+C in this terminal to stop the server.

## Run the client

Open a second PowerShell terminal in the same project folder and run:

```powershell
python -c "import secure_message; secure_message.run_client('127.0.0.1', 5300, 'www.example.com', 'A')"
```

The expected result is a verified answer for `192.168.1.10`. Another sample
record is `mail.example.com A`, which resolves to `192.168.1.20`:

```powershell
python -c "import secure_message; secure_message.run_client('127.0.0.1', 5300, 'mail.example.com', 'A')"
```

The client uses the local `server_public.pem` file as its trust anchor. It
checks that the response key matches that trusted key; it does not trust a key
just because the server included it in the response.

## Tampering demonstrations

In `run_client()`, there is a commented tampering-test section immediately
after the response is received. Uncomment one test at a time, run the
client, then comment it again. The tests alter the address, transaction ID,
nonce, expiration, key ID, or signature. The client should reject each altered
response rather than accept its address.