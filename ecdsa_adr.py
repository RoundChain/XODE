#!/usr/bin/env python3
"""
XODE Client v3.0 - ECDSA Signature Edition
Supports automatic migration from v2.x HMAC wallet to v3.0 ECDSA wallet
"""

import socket
import json
import time
import hashlib
import hmac
import struct
import os
import sys
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# ============ Configuration ============
WALLET_FILE = "wallet.dat"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5555
MAGIC = b'XODE'
HEADER_SIZE = 8

# ============ ECDSA Utility Functions ============

def _load_ecdsa_private_key(private_key_hex):
    """Load ECDSA private key object from hex"""
    private_value = int(private_key_hex, 16)
    return ec.derive_private_key(private_value, ec.SECP256K1())


def _load_ecdsa_public_key(public_key_hex):
    """Load ECDSA public key object from hex (33-byte compressed format)"""
    public_bytes = bytes.fromhex(public_key_hex)
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_bytes)


def generate_keypair():
    """Generate ECDSA secp256k1 keypair"""
    private_key = ec.generate_private_key(ec.SECP256K1())
    private_bytes = private_key.private_numbers().private_value.to_bytes(32, 'big')
    private_key_hex = private_bytes.hex()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    public_key_hex = public_bytes.hex()
    return private_key_hex, public_key_hex


def sign_message_ecdsa(private_key_hex, message):
    """ECDSA Signature"""
    private_key = _load_ecdsa_private_key(private_key_hex)
    if isinstance(message, str):
        message = message.encode('utf-8')
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature.hex()


def build_sign_message(from_addr, to_addr, amount, nonce, timestamp=None):
    """Build structured signing message (consistent with server)"""
    data = {
        "from": from_addr,
        "to": to_addr,
        "amount": float(amount),
        "nonce": int(nonce)
    }
    if timestamp is not None:
        data["timestamp"] = float(timestamp)
    return json.dumps(data, sort_keys=True, separators=(',', ':'))


def public_key_to_address(public_key_hex):
    """Public key -> XODE address"""
    public_bytes = bytes.fromhex(public_key_hex)
    h1 = hashlib.sha256(public_bytes).digest()
    try:
        h2 = hashlib.new('ripemd160', h1).digest()
    except ValueError:
        # OpenSSL 3.0+ may not support ripemd160
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
        # Fallback: use first 20 bytes of SHA256
        h2 = hashlib.sha256(h1).digest()[:20]

    extra = int(hashlib.sha256(h2).hexdigest(), 16)
    num = int.from_bytes(h2, 'big')
    mixed = (num ^ extra) & ((1 << 128) - 1)

    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    result = ''
    n = mixed
    while n > 0:
        n, rem = divmod(n, 58)
        result = alphabet[rem] + result

    if len(result) < 16:
        fill_chars = hashlib.sha256(str(mixed).encode()).hexdigest()
        fill = ''
        for i in range(0, 64, 2):
            idx = int(fill_chars[i:i+2], 16) % 58
            fill += alphabet[idx]
        result = fill[:16 - len(result)] + result

    result = result[:16]
    return 'XODE' + result


# ============ Legacy HMAC Compatibility (Transition Period) ============

def sign_message_hmac(private_key_hex, message):
    """Legacy HMAC-SHA256 signature (compatibility mode)"""
    # Legacy public key is SHA256(private_key)[:64]
    public_key_hex = hashlib.sha256(bytes.fromhex(private_key_hex)).hexdigest()[:64]
    key = hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:32]
    expected_sig = hmac.new(
        key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return expected_sig


def build_sign_message_legacy(from_addr, to_addr, amount, nonce, timestamp=None):
    """Legacy message format (compatibility mode)"""
    if timestamp is not None:
        return f"{from_addr}{to_addr}{amount}{nonce}{timestamp}"
    return f"{from_addr}{to_addr}{amount}{nonce}"


# ============ Wallet Management (With Auto-Migration) ============

class Wallet:
    """
    XODE Wallet - Supports automatic migration from v1 HMAC to v2 ECDSA

    Migration Strategy:
    1. Detect legacy wallet (version: 1 or no version)
    2. Use SHA256 of old private key as seed to derive new ECDSA private key
    3. Generate new public key and address
    4. Backup old wallet, save new wallet
    5. Display old/new address comparison, remind user to update
    """

    def __init__(self):
        self.private_key = ""
        self.public_key = ""
        self.address = ""
        self.created_at = 0
        self.version = 2
        self.nonce = 0  # Transaction nonce counter
        self.load_or_create()

    def load_or_create(self):
        if os.path.exists(WALLET_FILE):
            try:
                with open(WALLET_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                wallet_version = data.get("version", 1)
                self.private_key = data.get("private_key", "")
                self.public_key = data.get("public_key", "")
                self.address = data.get("address", "")
                self.created_at = data.get("created_at", 0)
                self.nonce = data.get("nonce", 0)

                if wallet_version == 1:
                    print("[!] Legacy HMAC wallet detected, auto-migrating to ECDSA...")
                    self._migrate_from_v1()
                    return

                # Verify address
                expected = public_key_to_address(self.public_key)
                if self.address != expected:
                    print("[!] Wallet address does not match public key, regenerating...")
                    self.create_new()
                    return

                print("[✓] Wallet loaded (ECDSA): " + self.address)
                return

            except Exception as e:
                print("[!] Wallet load failed: " + str(e) + ", creating new wallet...")

        self.create_new()

    def _migrate_from_v1(self):
        """Migrate from HMAC v1 to ECDSA v2"""
        try:
            old_private = self.private_key
            old_address = self.address

            if len(old_private) != 64:
                print("[!] Old private key format abnormal, creating new wallet")
                self.create_new()
                return

            # Use SHA256 of old private key as new private key seed
            seed = hashlib.sha256(bytes.fromhex(old_private)).digest()
            new_private_hex = seed.hex()

            # Derive ECDSA keypair
            private_key = _load_ecdsa_private_key(new_private_hex)
            public_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint
            )
            new_public_hex = public_bytes.hex()
            new_address = public_key_to_address(new_public_hex)

            print("=" * 50)
            print("[!] Wallet migration complete!")
            print("  Old address: " + old_address)
            print("  New address: " + new_address)
            print("  ⚠️  Note: Your address has changed!")
            print("  Please inform senders of your new address, old address will not receive new transactions")
            print("=" * 50)

            self.private_key = new_private_hex
            self.public_key = new_public_hex
            self.address = new_address
            self.version = 2
            self.nonce = 0
            self.created_at = time.time()
            self.save()

            # Backup old wallet
            backup_file = WALLET_FILE + ".v1.backup." + str(int(time.time()))
            try:
                import shutil
                shutil.copy(WALLET_FILE, backup_file)
                print("[✓] Old wallet backed up to: " + backup_file)
            except Exception as e:
                print("[!] Backup failed: " + str(e))

        except Exception as e:
            print("[!] Migration failed: " + str(e) + ", creating new wallet")
            self.create_new()

    def create_new(self):
        self.private_key, self.public_key = generate_keypair()
        self.address = public_key_to_address(self.public_key)
        self.created_at = time.time()
        self.version = 2
        self.nonce = 0
        self.save()
        print("[✓] New wallet created (ECDSA): " + self.address)

    def save(self):
        data = {
            "private_key": self.private_key,
            "public_key": self.public_key,
            "address": self.address,
            "balance": 0,
            "created_at": self.created_at,
            "saved_at": time.time(),
            "version": self.version,
            "algorithm": "ECDSA-secp256k1",
            "nonce": self.nonce
        }
        try:
            with open(WALLET_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print("[!] Wallet save failed: " + str(e))

    def get_next_nonce(self):
        """Get and increment nonce"""
        self.nonce += 1
        self.save()
        return self.nonce

    def sign_transfer(self, to_addr, amount):
        """
        Sign transfer transaction
        Returns: (signature, nonce, timestamp, message)
        """
        nonce = self.get_next_nonce()
        timestamp = time.time()

        message = build_sign_message(self.address, to_addr, amount, nonce, timestamp)
        signature = sign_message_ecdsa(self.private_key, message)

        return signature, nonce, timestamp, message

    def get_info(self):
        return {
            "address": self.address,
            "public_key": self.public_key,
            "version": self.version,
            "nonce": self.nonce
        }


# ============ Network Communication ============

def encode_message(payload_dict):
    payload = json.dumps(payload_dict, ensure_ascii=False).encode('utf-8')
    length = len(payload)
    return MAGIC + struct.pack('>I', length) + payload


def decode_messages(buffer):
    messages = []
    while True:
        idx = buffer.find(MAGIC)
        if idx == -1:
            return messages, b""
        buffer = buffer[idx:]
        if len(buffer) < HEADER_SIZE:
            return messages, buffer
        length = struct.unpack('>I', buffer[4:8])[0]
        if length > 10_000_000 or length < 0:
            buffer = buffer[4:]
            continue
        if len(buffer) < HEADER_SIZE + length:
            return messages, buffer
        payload = buffer[HEADER_SIZE:HEADER_SIZE + length]
        buffer = buffer[HEADER_SIZE + length:]
        try:
            msg = json.loads(payload.decode('utf-8'))
            messages.append(msg)
        except:
            pass
    return messages, buffer


# ============ XODE Client ============

class XodeClient:
    """XODE Blockchain Client v3.0"""

    def __init__(self, host=SERVER_HOST, port=SERVER_PORT):
        self.host = host
        self.port = port
        self.socket = None
        self.wallet = Wallet()
        self.buffer = b""
        self.connected = False
        self.server_info = {}

    def connect(self):
        """Connect to server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
            self.socket.settimeout(None)

            # Send connection message (includes public key and version info)
            init_msg = {
                "type": "connect",
                "address": self.wallet.address,
                "public_key": self.wallet.public_key,
                "version": 3.0,
                "algorithm": "ECDSA-secp256k1"
            }
            self.socket.sendall(encode_message(init_msg))

            # Wait for server response
            data = self.socket.recv(4096)
            messages, self.buffer = decode_messages(data)

            if messages:
                response = messages[0]
                if response.get("type") == "connected":
                    self.connected = True
                    self.server_info = response
                    print("[✓] Connected to server")
                    print("  Balance: " + str(response.get("balance", 0)) + " XODE")
                    print("  Block height: " + str(response.get("block_height", 0)))

                    # Display reward delay info
                    if not response.get("reward_eligible", True):
                        remaining = response.get("blocks_remaining", 0)
                        print("  ⏳ Need to wait " + str(remaining) + " more blocks for reward eligibility")

                    return True
                elif response.get("type") == "error":
                    print("[✗] Connection rejected: " + response.get("error", "Unknown error"))

                    # Check for version incompatibility
                    if "public key" in response.get("error", "") or "mismatch" in response.get("error", ""):
                        print("[!] Server version may be incompatible, please confirm server is upgraded to v3.0+")

                    self.socket.close()
                    return False

            print("[✗] Connection response abnormal")
            self.socket.close()
            return False

        except Exception as e:
            print("[✗] Connection failed: " + str(e))
            return False

    def transfer(self, to_addr, amount):
        """Send transfer transaction"""
        if not self.connected:
            print("[!] Not connected to server")
            return False

        # Sign transaction
        signature, nonce, timestamp, message = self.wallet.sign_transfer(to_addr, amount)

        tx_msg = {
            "type": "transfer",
            "to": to_addr,
            "amount": amount,
            "signature": signature,
            "public_key": self.wallet.public_key,
            "timestamp": timestamp,
            "nonce": nonce
        }

        try:
            self.socket.sendall(encode_message(tx_msg))

            # Wait for response
            data = self.socket.recv(4096)
            messages, self.buffer = decode_messages(self.buffer + data)

            for msg in messages:
                if msg.get("type") == "transfer_result":
                    if msg.get("success"):
                        print("[✓] Transfer successful!")
                        print("  Balance: " + str(msg.get("balance", 0)) + " XODE")
                        return True
                    else:
                        print("[✗] Transfer failed: " + msg.get("error", "Unknown error"))
                        return False

            print("[!] No transfer response received")
            return False

        except Exception as e:
            print("[✗] Transfer send failed: " + str(e))
            self.connected = False
            return False

    def get_balance(self):
        """Query balance"""
        if not self.connected:
            return 0

        try:
            self.socket.sendall(encode_message({"type": "get_balance"}))
            data = self.socket.recv(4096)
            messages, self.buffer = decode_messages(self.buffer + data)

            for msg in messages:
                if msg.get("type") == "balance":
                    return msg.get("balance", 0)
            return 0
        except:
            return 0

    def ping(self):
        """Send heartbeat"""
        if not self.connected:
            return False
        try:
            self.socket.sendall(encode_message({"type": "ping"}))
            return True
        except:
            self.connected = False
            return False

    def close(self):
        """Close connection"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.connected = False
        print("[✓] Connection closed")


# ============ CLI Interaction ============

def main():
    print("=" * 50)
    print("XODE Client v3.0 [ECDSA Signature Edition]")
    print("=" * 50)

    # Initialize wallet (auto-migrate legacy wallet)
    client = XodeClient()

    if not client.connect():
        print("[!] Cannot connect to server, exiting")
        return

    print("\nAvailable commands:")
    print("  transfer <address> <amount>  - Transfer")
    print("  balance                - Query balance")
    print("  info                 - Show wallet info")
    print("  ping                 - Send heartbeat")
    print("  quit                 - Exit")
    print("")

    try:
        while True:
            try:
                cmd = input("XODE> ").strip()
            except EOFError:
                break

            if not cmd:
                continue

            parts = cmd.split()
            action = parts[0].lower()

            if action == "quit" or action == "exit":
                break

            elif action == "transfer":
                if len(parts) != 3:
                    print("Usage: transfer <address> <amount>")
                    continue
                to_addr = parts[1]
                try:
                    amount = float(parts[2])
                except:
                    print("[!] Amount must be a number")
                    continue
                client.transfer(to_addr, amount)

            elif action == "balance":
                bal = client.get_balance()
                print("[Balance] " + str(bal) + " XODE")

            elif action == "info":
                info = client.wallet.get_info()
                print("[Wallet Info]")
                print("  address: " + info["address"])
                print("  public key: " + info["public_key"][:20] + "...")
                print("  Version: " + str(info["version"]))
                print("  Nonce: " + str(info["nonce"]))

            elif action == "ping":
                if client.ping():
                    print("[✓] Heartbeat sent")
                else:
                    print("[✗] Heartbeat failed")

            else:
                print("[!] Unknown command: " + action)

    except KeyboardInterrupt:
        print("\n[!] User interrupted")

    finally:
        client.close()


if __name__ == "__main__":
    main()
