import math
import socket
import threading
import json
import time
import hashlib
import sys
import os
import secrets
import struct
from decimal import Decimal, ROUND_DOWN

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

import http.server
import socketserver
from urllib.parse import parse_qs, urlparse
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)

from datetime import datetime, timezone

DATA_FILE = "xodechain.json"
WALLET_FILE = "wallet.dat"
PEERS_CONFIG_FILE = "peers.txt"
BURN_ADDRESS = "XODE0000000000000000"
CLIENT_FILE = "client.txt"
HISTORY_FILE = "my_history.json"

MAGIC = b'XODE'
MAX_PAYLOAD_SIZE = 20_000_000

MAX_TX_PER_BLOCK = 1000
MAX_BLOCK_SIZE = 10_000_000
MAX_MEMPOOL_SIZE = 5000
TX_MAX_LIFETIME = 86400

HEADER_SIZE = 8

BIND_TIMEOUT = 3600
TX_CONFIRMATIONS = 6
REWARD_CONFIRMATIONS = 30
BLOCKS_BEFORE_REWARD = 15
BLOCK_TIME = 120

INITIAL_DIFFICULTY = 24.0
DIFFICULTY_ADJUSTMENT_INTERVAL = 10

PRODUCER_REWARD_SHARE = 0.20
ONLINE_REWARD_SHARE = 0.80

MAX_TRANSFER_AMOUNT = 10_000_000_000_000_000
MAX_DAILY_TRANSFER_COUNT = 1000
MAX_DAILY_TRANSFER_AMOUNT = 100_000_000_000_000_000

MAX_ORPHAN_BLOCKS = 5000
MAX_HEADERS_RESULTS = 500
MAX_BLOCKS_PER_GETDATA = 5
MAX_INV_SIZE = 50000
SYNC_TIMEOUT = 3600


def _load_json_data():
    if not os.path.exists(DATA_FILE):
        return None
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"加载失败: {e}", flush=True)
        return None


def _save_json_data(data):
    try:
        temp_file = DATA_FILE + ".tmp"
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        if os.path.exists(DATA_FILE):
            os.replace(temp_file, DATA_FILE)
        else:
            os.rename(temp_file, DATA_FILE)
        return True
    except Exception as e:
        print(f"保存失败: {e}", flush=True)
        return False


class PureRIPEMD160:
    def __init__(self):
        self.buf = b''
        self.count = 0
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    def _rol(self, n, k):
        return ((n << k) | (n >> (32 - k))) & 0xFFFFFFFF

    def _compress(self, chunk):
        X = [int.from_bytes(chunk[i*4:(i+1)*4], 'little') for i in range(16)]
        h = self.h[:]
        A, B, C, D, E = h
        for j in range(16):
            T = (self._rol(A + ((B ^ C ^ D) + X[j] + 0x00000000) & 0xFFFFFFFF, self._r1[j]) + E) & 0xFFFFFFFF
            A, B, C, D, E = E, T, B, self._rol(C, 10), D
        for j in range(16):
            T = (self._rol(A + (((C ^ D) & B) ^ D) + X[self._r2[j]] + 0x5A827999, self._s1[j]) + E) & 0xFFFFFFFF
            A, B, C, D, E = E, T, B, self._rol(C, 10), D
        for j in range(16):
            T = (self._rol(A + ((B | ~C) ^ D) + X[self._r3[j]] + 0x6ED9EBA1, self._s2[j]) + E) & 0xFFFFFFFF
            A, B, C, D, E = E, T, B, self._rol(C, 10), D
        for j in range(16):
            T = (self._rol(A + (((B ^ C) & D) ^ C) + X[self._r4[j]] + 0x8F1BBCDC, self._s3[j]) + E) & 0xFFFFFFFF
            A, B, C, D, E = E, T, B, self._rol(C, 10), D
        for j in range(16):
            T = (self._rol(A + (B ^ (C | ~D)) + X[self._r5[j]] + 0xA953FD4E, self._s4[j]) + E) & 0xFFFFFFFF
            A, B, C, D, E = E, T, B, self._rol(C, 10), D
        AA, BB, CC, DD, EE = h[0], h[1], h[2], h[3], h[4]
        for j in range(16):
            T = (self._rol(AA + (BB ^ (CC | ~DD)) + X[self._r5[j]] + 0x50A28BE6, self._t1[j]) + EE) & 0xFFFFFFFF
            AA, BB, CC, DD, EE = EE, T, BB, self._rol(CC, 10), DD
        for j in range(16):
            T = (self._rol(AA + (((BB ^ CC) & DD) ^ CC) + X[self._r4[j]] + 0x5C4DD124, self._t2[j]) + EE) & 0xFFFFFFFF
            AA, BB, CC, DD, EE = EE, T, BB, self._rol(CC, 10), DD
        for j in range(16):
            T = (self._rol(AA + ((BB | ~CC) ^ DD) + X[self._r3[j]] + 0x6D703EF3, self._t3[j]) + EE) & 0xFFFFFFFF
            AA, BB, CC, DD, EE = EE, T, BB, self._rol(CC, 10), DD
        for j in range(16):
            T = (self._rol(AA + (((CC ^ DD) & BB) ^ DD) + X[self._r2[j]] + 0x7A6D76E9, self._t4[j]) + EE) & 0xFFFFFFFF
            AA, BB, CC, DD, EE = EE, T, BB, self._rol(CC, 10), DD
        for j in range(16):
            T = (self._rol(AA + (BB ^ CC ^ DD) + X[j] + 0x00000000, self._t5[j]) + EE) & 0xFFFFFFFF
            AA, BB, CC, DD, EE = EE, T, BB, self._rol(CC, 10), DD
        T = (h[1] + C + DD) & 0xFFFFFFFF
        self.h = [
            (h[0] + A + EE) & 0xFFFFFFFF,
            T,
            (h[2] + E + AA) & 0xFFFFFFFF,
            (h[3] + B + CC) & 0xFFFFFFFF,
            (h[4] + D + BB) & 0xFFFFFFFF
        ]

    _r1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
    _r2 = [7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8]
    _r3 = [3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12]
    _r4 = [1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2]
    _r5 = [4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    _s1 = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8]
    _s2 = [7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12]
    _s3 = [11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5]
    _s4 = [11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12]
    _t1 = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6]
    _t2 = [9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11]
    _t3 = [9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5]
    _t4 = [15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8]
    _t5 = [8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]

    def update(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.buf += data
        self.count += len(data)
        while len(self.buf) >= 64:
            self._compress(self.buf[:64])
            self.buf = self.buf[64:]
        return self

    def digest(self):
        count = (self.count * 8) & 0xFFFFFFFFFFFFFFFF
        pad = b'\x80' + b'\x00' * ((55 - self.count) % 64)
        pad += count.to_bytes(8, 'little')
        self.update(pad)
        result = b''.join(h.to_bytes(4, 'little') for h in self.h)
        return result

    def hexdigest(self):
        return self.digest().hex()


def _get_ripemd160():
    try:
        md = hashlib.new('ripemd160')
        return hashlib.new
    except ValueError:
        def new_ripemd160(name):
            if name.lower() == 'ripemd160':
                return PureRIPEMD160()
            return hashlib.new(name)
        return new_ripemd160


AMOUNT_PRECISION = 8
AMOUNT_FACTOR = 10 ** AMOUNT_PRECISION

def to_atomic(amount):
    if amount is None:
        return 0
    try:
        d = Decimal(str(amount)) * Decimal(AMOUNT_FACTOR)
        return int(d.quantize(Decimal('1'), rounding=ROUND_DOWN))
    except:
        return int(float(amount) * AMOUNT_FACTOR)

def from_atomic(amount):
    if amount is None:
        return 0.0
    return round(amount / AMOUNT_FACTOR, AMOUNT_PRECISION)

def format_amount(amount):
    return f"{from_atomic(amount):.{AMOUNT_PRECISION}f}"


def canonical_json(obj):
    if isinstance(obj, dict):
        return {k: canonical_json(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [canonical_json(v) for v in obj]
    return obj


def difficulty_to_target(difficulty):
    import math
    return int(2 ** (256 - float(difficulty)))


def target_to_difficulty(target):
    import math
    if target <= 0:
        return 256.0
    return 256.0 - math.log2(float(target))


def _load_ecdsa_private_key(private_key_hex):
    private_value = int(private_key_hex, 16)
    return ec.derive_private_key(private_value, ec.SECP256K1())


def _load_ecdsa_public_key(public_key_hex):
    public_bytes = bytes.fromhex(public_key_hex)
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_bytes)


def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256K1())
    private_bytes = private_key.private_numbers().private_value.to_bytes(32, 'big')
    private_key_hex = private_bytes.hex()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    public_key_hex = public_bytes.hex()
    return private_key_hex, public_key_hex


def sign_message(private_key_hex, message):
    private_key = _load_ecdsa_private_key(private_key_hex)
    if isinstance(message, str):
        message = message.encode('utf-8')
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature.hex()


def verify_signature(public_key_hex, message, signature_hex, timestamp=None):
    if not public_key_hex or not signature_hex or not message:
        return False
    try:
        if timestamp is not None:
            current_time = time.time()
            if abs(current_time - timestamp) > 3600000000000000000000000000000000:
                print(f"[签名验证] 时间戳过期: {timestamp}, 当前: {current_time}", flush=True)
                return False
        public_key = _load_ecdsa_public_key(public_key_hex)
        signature = bytes.fromhex(signature_hex)
        if isinstance(message, str):
            message = message.encode('utf-8')
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        print("[签名验证] ECDSA 签名无效", flush=True)
        return False
    except Exception as e:
        print("[签名验证] 验证异常: " + str(e), flush=True)
        return False


def public_key_to_address(public_key_hex):
    public_bytes = bytes.fromhex(public_key_hex)
    h1 = hashlib.sha256(public_bytes).digest()
    ripemd160_new = _get_ripemd160()
    h2_obj = ripemd160_new('ripemd160')
    h2_obj.update(h1)
    h2 = h2_obj.digest()
    num = int.from_bytes(h2, 'big')
    extra = int(hashlib.sha256(h2).hexdigest(), 16)
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


def verify_public_key_address(public_key_hex, address):
    if not public_key_hex or not address:
        return False
    try:
        expected = public_key_to_address(public_key_hex)
        return expected == address
    except Exception:
        return False


def build_sign_message(from_addr, to_addr, amount, nonce, timestamp=None):
    atomic_amount = to_atomic(amount)
    data = {
        "from": from_addr,
        "to": to_addr,
        "amount": atomic_amount,
        "nonce": int(nonce)
    }
    if timestamp is not None:
        data["timestamp"] = float(timestamp)
    return json.dumps(data, sort_keys=True, separators=(',', ':'))



def compute_block_hash(index, timestamp, previous_hash, reward_tx, transactions, nonce, difficulty):
    clean_reward = None
    if reward_tx:
        clean_reward = {
            "total_atomic": to_atomic(reward_tx.get("total", 0)),
            "burned_atomic": reward_tx.get("burned_atomic", 0) or 0,
            "producer_reward_atomic": reward_tx.get("producer_reward_atomic", 0) or 0,
            "reward_per_user_atomic": reward_tx.get("reward_per_user_atomic", 0) or 0,
            "producer_node": reward_tx.get("producer_node", ""),
            "producer_eligible": reward_tx.get("producer_eligible", False),
            "recipients": sorted([
                {
                    "address": r.get("address", ""),
                    "amount_atomic": r.get("amount_atomic", 0) or 0,
                    "is_producer": r.get("is_producer", False)
                }
                for r in reward_tx.get("recipients", [])
            ], key=lambda x: x["address"])
        }

    clean_txs = []
    for tx in (transactions or []):
        clean_tx = {
            "type": tx.get("type", "transfer"),
            "from": tx.get("from", ""),
            "to": tx.get("to", ""),
            "amount_atomic": tx.get("amount_atomic", 0) or 0,
            "fee_atomic": tx.get("fee_atomic", 0) or 0,
            "nonce": tx.get("nonce", 0),
        }
        if tx.get("signature"):
            clean_tx["signature"] = tx["signature"]
        if tx.get("public_key"):
            clean_tx["public_key"] = tx.get("public_key")
        if tx.get("tx_hash"):
            clean_tx["tx_hash"] = tx.get("tx_hash")
        clean_txs.append(clean_tx)

    block_data = {
        "index": index,
        "timestamp": timestamp,
        "previous_hash": previous_hash,
        "reward_tx": clean_reward,
        "transactions": clean_txs,
        "nonce": nonce,
        "difficulty": difficulty
    }
    block_string = json.dumps(canonical_json(block_data), separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(block_string.encode('utf-8')).hexdigest()


class Block:
    def __init__(self, index, timestamp, previous_hash, reward_tx, transactions=None, nonce=0, difficulty=4.0, hash=None):
        self.index = index
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.reward_tx = reward_tx
        self.transactions = transactions or []
        self.nonce = nonce
        self.difficulty = float(difficulty)
        self.hash = hash if hash is not None else self.calculate_hash()

    def calculate_hash(self):
        return compute_block_hash(
            self.index, self.timestamp, self.previous_hash,
            self.reward_tx, self.transactions, self.nonce, self.difficulty
        )

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
            "reward_tx": self.reward_tx,
            "transactions": self.transactions,
            "nonce": self.nonce,
            "difficulty": self.difficulty
        }

    @classmethod
    def from_dict(cls, data):
        block = cls(
            index=data["index"],
            timestamp=int(data["timestamp"]),
            previous_hash=data["previous_hash"],
            reward_tx=data["reward_tx"],
            transactions=data.get("transactions", []),
            nonce=data.get("nonce", 0),
            difficulty=float(data.get("difficulty", 4.0)),
            hash=data.get("hash")
        )
        return block


class ServerWallet:
    def __init__(self):
        self.private_key = ""
        self.public_key = ""
        self.address = ""
        self.created_at = 0
        self.version = 2
        self.load_or_create()

    def load_or_create(self):
        if os.path.exists(WALLET_FILE):
            try:
                with open(WALLET_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.private_key = data.get("private_key", "")
                self.public_key = data.get("public_key", "")
                self.address = data.get("address", "")
                self.created_at = data.get("created_at", 0)
                expected_addr = public_key_to_address(self.public_key)
                if self.address != expected_addr:
                    print("[Wallet] WARNING: Address mismatch! Expected " + expected_addr + ", got " + self.address)
                    print("[Wallet] Regenerating wallet...")
                    self.create_new()
                    return
                print("[Wallet] Loaded (ECDSA): " + self.address)
                return
            except Exception as e:
                print("[Wallet] Failed to load: " + str(e) + ", creating new...")
        self.create_new()

    def create_new(self):
        self.private_key, self.public_key = generate_keypair()
        self.address = public_key_to_address(self.public_key)
        self.created_at = time.time()
        self.version = 2
        self.save()
        print("[Wallet] Created new (ECDSA): " + self.address)

    def save(self):
        data = {
            "private_key": self.private_key,
            "public_key": self.public_key,
            "address": self.address,
            "balance": 0,
            "created_at": self.created_at,
            "saved_at": time.time(),
            "version": self.version,
            "algorithm": "ECDSA-secp256k1"
        }
        try:
            with open(WALLET_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print("[Wallet] Saved to: " + WALLET_FILE)
        except Exception as e:
            print("[Wallet] Save failed: " + str(e))

    def get_info(self):
        return {
            "address": self.address,
            "public_key": self.public_key,
            "created_at": self.created_at,
            "version": self.version
        }

    def sign(self, message):
        return sign_message(self.private_key, message)


def encode_message(payload_dict):
    payload = json.dumps(payload_dict, ensure_ascii=False).encode('utf-8')
    length = len(payload)
    if length > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload too large: {length} bytes")
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
        if length > MAX_PAYLOAD_SIZE or length < 0:
            buffer = buffer[4:]
            continue
        if len(buffer) < HEADER_SIZE + length:
            return messages, buffer
        payload = buffer[HEADER_SIZE:HEADER_SIZE + length]
        buffer = buffer[HEADER_SIZE + length:]
        try:
            msg = json.loads(payload.decode('utf-8'))
            messages.append(msg)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    return messages, buffer

# ============ HTML Page ============
HTML_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>XODE Web Client</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);color:#e0e6ed;min-height:100vh;overflow-x:hidden}
.bg-particles{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0}
.particle{position:absolute;border-radius:50%;background:rgba(0,212,255,0.06);animation:float 20s infinite}
@keyframes float{0%,100%{transform:translateY(0) rotate(0deg)}50%{transform:translateY(-100px) rotate(180deg)}}
.nav-bar{position:sticky;top:0;z-index:100;background:rgba(15,15,35,0.7);backdrop-filter:blur(20px);border-bottom:1px solid rgba(255,255,255,0.08);padding:0 24px;height:64px;display:flex;align-items:center;justify-content:space-between}
.nav-brand{display:flex;align-items:center;gap:12px}
.nav-brand .logo{width:36px;height:36px;background:linear-gradient(135deg,#00d4ff,#7b2cbf);border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:16px;color:#fff}
.nav-brand h1{font-size:18px;font-weight:700;background:linear-gradient(90deg,#00d4ff,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.nav-brand .tag{font-size:11px;color:#6b7a8f;margin-left:8px;padding:2px 8px;background:rgba(255,255,255,0.05);border-radius:6px}
.status-pill{padding:6px 14px;border-radius:20px;font-size:12px;font-weight:600;display:inline-flex;align-items:center;gap:6px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1)}
.status-pill.connected{background:rgba(34,197,94,0.15);border-color:rgba(34,197,94,0.3);color:#22c55e}
.status-pill.disconnected{background:rgba(239,68,68,0.15);border-color:rgba(239,68,68,0.3);color:#ef4444}
.pulse-dot{width:8px;height:8px;border-radius:50%;animation:pulse 2s infinite}
.connected .pulse-dot{background:#22c55e}
.disconnected .pulse-dot{background:#ef4444;animation:none}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(34,197,94,0.4)}50%{opacity:.7;box-shadow:0 0 0 6px rgba(34,197,94,0)}}
.main-layout{display:grid;grid-template-columns:260px 1fr;gap:24px;padding:24px;max-width:1800px;margin:0 auto;position:relative;z-index:1}
@media(max-width:1024px){.main-layout{grid-template-columns:1fr}}
.sidebar{display:flex;flex-direction:column;gap:12px;min-width:0}
.sidebar-card{background:rgba(255,255,255,0.03);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.08);border-radius:20px;padding:24px}
.wallet-card{text-align:center;padding:28px 20px}
.wallet-avatar{width:64px;height:64px;background:linear-gradient(135deg,#00d4ff,#7b2cbf);border-radius:50%;margin:0 auto 16px;display:flex;align-items:center;justify-content:center;font-size:24px}
.balance-amount{font-size:28px;font-weight:800;background:linear-gradient(90deg,#00d4ff,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;line-height:1.3;word-break:break-all;overflow-wrap:break-word}
.balance-label{font-size:12px;color:#6b7a8f;margin-top:4px;text-transform:uppercase;letter-spacing:2px}
.address-box{margin-top:16px;padding:10px 12px;background:rgba(0,0,0,0.2);border-radius:12px;font-family:monospace;font-size:10px;color:#00d4ff;word-break:break-all;border:1px solid rgba(0,212,255,0.15);line-height:1.5}
.nav-menu{display:flex;flex-direction:column;gap:4px}
.nav-item{padding:12px 16px;border-radius:12px;font-size:14px;font-weight:500;color:#8b95a5;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:10px;border:none;background:transparent;width:100%;text-align:left}
.nav-item:hover{background:rgba(255,255,255,0.05);color:#e0e6ed}
.nav-item.active{background:linear-gradient(135deg,rgba(0,212,255,0.15),rgba(123,44,191,0.1));color:#00d4ff;border:1px solid rgba(0,212,255,0.2)}
.nav-icon{width:20px;height:20px;display:flex;align-items:center;justify-content:center;font-size:14px}
.content-area{display:flex;flex-direction:column;gap:20px;min-width:0}
.glass-card{background:rgba(255,255,255,0.03);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.08);border-radius:20px;padding:24px;transition:all .3s;min-width:0}
.glass-card:hover{border-color:rgba(255,255,255,0.12)}
.section-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.section-title{font-size:16px;font-weight:700;display:flex;align-items:center;gap:10px}
.section-title::before{content:'';width:4px;height:20px;background:linear-gradient(180deg,#00d4ff,#7b2cbf);border-radius:2px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;margin-bottom:20px}
.stat-card{background:rgba(255,255,255,0.03);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:20px;position:relative;overflow:hidden;min-width:0}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#00d4ff,#7b2cbf);opacity:0;transition:opacity .3s}
.stat-card:hover::before{opacity:1}
.stat-card:hover{transform:translateY(-2px);border-color:rgba(255,255,255,0.15)}
.stat-icon{position:absolute;top:16px;right:16px;width:32px;height:32px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:14px;background:rgba(0,212,255,0.1);color:#00d4ff}
.stat-icon.purple{background:rgba(168,85,247,0.1);color:#a855f7}
.stat-icon.green{background:rgba(34,197,94,0.1);color:#22c55e}
.stat-icon.orange{background:rgba(249,115,22,0.1);color:#f97316}
.stat-icon.red{background:rgba(239,68,68,0.1);color:#ef4444}
.stat-label{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:#6b7a8f;margin-bottom:8px;padding-right:40px}
.stat-value{font-size:22px;font-weight:800;color:#f0f4f8;line-height:1.2;word-break:break-all;overflow-wrap:break-word}
.stat-sub{font-size:12px;color:#4a5568;margin-top:6px;word-break:break-word}
.progress-track{width:100%;height:8px;background:rgba(0,0,0,0.3);border-radius:4px;overflow:hidden;margin-top:12px}
.progress-fill{height:100%;background:linear-gradient(90deg,#00d4ff,#7b2cbf);border-radius:4px;transition:width .6s ease;position:relative}
.progress-fill::after{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.3),transparent);animation:shimmer 2s infinite}
@keyframes shimmer{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}
.form-grid{display:grid;grid-template-columns:2fr 1fr 1fr;gap:16px}
@media(max-width:768px){.form-grid{grid-template-columns:1fr}}
.form-group label{display:block;font-size:12px;color:#6b7a8f;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px}
.form-group input,.form-group select{width:100%;padding:14px 16px;background:rgba(0,0,0,0.25);border:1px solid rgba(255,255,255,0.1);border-radius:12px;color:#e0e6ed;font-size:14px;outline:none;transition:all .2s}
.form-group input:focus,.form-group select:focus{border-color:#00d4ff;box-shadow:0 0 0 3px rgba(0,212,255,0.1)}
.form-group input::placeholder{color:#4a5568}
.btn{padding:14px 28px;border:none;border-radius:12px;font-size:14px;font-weight:600;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:8px}
.btn-primary{background:linear-gradient(135deg,#00d4ff,#0099cc);color:#000;box-shadow:0 4px 20px rgba(0,212,255,0.25)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(0,212,255,0.35)}
.btn-danger{background:linear-gradient(135deg,#ef4444,#dc2626);color:#fff;box-shadow:0 4px 20px rgba(239,68,68,0.25)}
.btn-danger:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(239,68,68,0.35)}
.btn-secondary{background:rgba(255,255,255,0.05);color:#e0e6ed;border:1px solid rgba(255,255,255,0.1)}
.btn-secondary:hover{background:rgba(255,255,255,0.1)}
.btn:disabled{opacity:.4;cursor:not-allowed;transform:none!important}
.tab-content{display:none}
.tab-content.active{display:block}
.block-card{background:rgba(0,0,0,0.2);border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:18px;margin-bottom:12px;transition:all .2s}
.block-card:hover{border-color:rgba(0,212,255,0.2);transform:translateX(4px)}
.block-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.block-num{font-size:20px;font-weight:800;color:#00d4ff}
.block-hash{font-family:monospace;font-size:11px;color:#4a5568;background:rgba(0,0,0,0.3);padding:4px 10px;border-radius:6px}
.block-meta{display:flex;gap:20px;font-size:12px;color:#6b7a8f;flex-wrap:wrap}
.block-meta span{display:flex;align-items:center;gap:4px}
.tx-item{background:rgba(0,0,0,0.2);border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:16px;margin-bottom:10px;display:grid;grid-template-columns:auto 1fr auto;gap:16px;align-items:center;transition:all .2s}
.tx-item:hover{border-color:rgba(255,255,255,0.12)}
.tx-icon{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:18px}
.tx-icon.sent{background:rgba(239,68,68,0.1);color:#ef4444}
.tx-icon.received{background:rgba(34,197,94,0.1);color:#22c55e}
.tx-icon.reward{background:rgba(0,212,255,0.1);color:#00d4ff}
.tx-details{min-width:0}
.tx-type{font-size:14px;font-weight:600;color:#f0f4f8}
.tx-addr{font-size:11px;color:#4a5568;font-family:monospace;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tx-amount{text-align:right}
.tx-amount-value{font-size:16px;font-weight:700;color:#00d4ff}
.tx-amount-fee{font-size:11px;color:#f97316;margin-top:2px}
.log-container{background:rgba(0,0,0,0.25);border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:16px;height:400px;overflow-y:auto;font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.8}
.log-entry{padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.03);display:flex;gap:12px}
.log-time{color:#4a5568;flex-shrink:0}
.log-info{color:#00d4ff}.log-success{color:#22c55e}.log-error{color:#ef4444}.log-warning{color:#f97316}
.toast-container{position:fixed;top:20px;right:20px;z-index:1000;display:flex;flex-direction:column;gap:10px}
.toast{padding:16px 24px;border-radius:14px;font-size:14px;font-weight:500;animation:slideIn .4s cubic-bezier(0.16,1,0.3,1);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.1)}
.toast-success{background:rgba(34,197,94,0.15);color:#22c55e;border-color:rgba(34,197,94,0.3)}
.toast-error{background:rgba(239,68,68,0.15);color:#ef4444;border-color:rgba(239,68,68,0.3)}
.toast-info{background:rgba(0,212,255,0.15);color:#00d4ff;border-color:rgba(0,212,255,0.3)}
@keyframes slideIn{from{transform:translateX(120%);opacity:0}to{transform:translateX(0);opacity:1}}
.sync-badge{display:inline-flex;align-items:center;gap:8px;padding:6px 14px;background:rgba(249,115,22,0.1);border:1px solid rgba(249,115,22,0.2);border-radius:20px;color:#f97316;font-size:12px;font-weight:600}
.spinner{width:14px;height:14px;border:2px solid #f97316;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.danger-zone{background:rgba(239,68,68,0.05);border:1px solid rgba(239,68,68,0.2);border-radius:16px;padding:20px;margin-top:20px}
.danger-title{color:#ef4444;font-weight:700;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.empty-state{text-align:center;padding:60px 20px;color:#4a5568}
.empty-state-icon{font-size:48px;margin-bottom:16px;opacity:.5}
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.1);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,0.2)}
@media(max-width:768px){
.main-layout{padding:12px;gap:16px}
.stats-grid{grid-template-columns:1fr}
.stat-value{font-size:18px}
.tx-item{grid-template-columns:1fr;gap:8px;text-align:center}
.tx-amount{text-align:center}
}
.rank-row:hover{background:rgba(255,255,255,0.03)!important}</style>
</head>
<body>
<div class="bg-particles" id="particles"></div>
<div class="nav-bar">
  <div class="nav-brand">
    <div class="logo"></div>
    <h1>XODE Wallet</h1>
    <span class="tag">ECDSA secp256k1</span>
  </div>
  <div id="connectionStatus" class="status-pill disconnected">
    <span class="pulse-dot"></span>
    <span id="statusText">Disconnected</span>
  </div>
</div>
<div class="main-layout">
  <aside class="sidebar">
    <div class="sidebar-card wallet-card">
      <div class="wallet-avatar">XODE</div>
      <div class="balance-amount" id="walletBalanceDisplay">0.00000000</div>
      <div class="balance-label">XODE BALANCE</div>
      <div class="address-box" id="addressDisplay">---</div>
      <div style="margin-top:12px;display:flex;gap:8px;justify-content:center">
        <div style="text-align:center">
          <div style="font-size:11px;color:#6b7a8f">Available</div>
          <div style="font-size:14px;font-weight:600;color:#22c55e" id="availableBalanceDisplay">0.00</div>
        </div>
        <div style="width:1px;background:rgba(255,255,255,0.1)"></div>
        <div style="text-align:center">
          <div style="font-size:11px;color:#6b7a8f">Locked</div>
          <div style="font-size:14px;font-weight:600;color:#f97316" id="lockedBalanceDisplay">0.00</div>
        </div>
      </div>
    </div>
    <div class="sidebar-card" style="padding:12px">
      <div class="nav-menu">
        <button class="nav-item active" onclick="switchTab('connect',this)"><span class="nav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></span> Connect</button>
        <button class="nav-item" onclick="switchTab('transfer',this)"><span class="nav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="1" x2="12" y2="23"></line><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path></svg></span> Transfer</button>
        <button class="nav-item" onclick="switchTab('blocks',this)"><span class="nav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg></span> Blocks</button>
        <button class="nav-item" onclick="switchTab('history',this)"><span class="nav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg></span> History</button>
        <button class="nav-item" onclick="switchTab('wallet',this)"><span class="nav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg></span> Wallet</button>
        <button class="nav-item" onclick="switchTab('logs',this)"><span class="nav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></span> Logs</button>
        <button class="nav-item" onclick="switchTab('rankings',this)"><span class="nav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20V10"></path><path d="M18 20V4"></path><path d="M6 20v-4"></path></svg></span> Rankings</button>
      </div>
    </div>
    <div class="sidebar-card">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:#6b7a8f;margin-bottom:12px">Network</div>
      <div style="display:flex;flex-direction:column;gap:10px">
        <div style="display:flex;justify-content:space-between;font-size:13px"><span style="color:#4a5568">Block Time</span><span style="color:#00d4ff;font-weight:600" id="blockTime">120s</span></div>
        <div style="display:flex;justify-content:space-between;font-size:13px"><span style="color:#4a5568">Reward</span><span style="color:#a855f7;font-weight:600" id="blockReward">1000 XODE</span></div>
        <div style="display:flex;justify-content:space-between;font-size:13px"><span style="color:#4a5568">Fee</span><span style="color:#f97316;font-weight:600" id="transferFee">1 XODE</span></div>
        <div style="display:flex;justify-content:space-between;font-size:13px"><span style="color:#4a5568">Pending</span><span style="color:#e0e6ed;font-weight:600" id="pendingTx">0</span></div>
      </div>
    </div>
  </aside>
  <main class="content-area">
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg></div><div class="stat-label">Block Height</div><div class="stat-value" id="blockHeightDisplay">0</div><div class="stat-sub" id="syncStatus">Not synced</div></div>
      <div class="stat-card"><div class="stat-icon purple"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg></div><div class="stat-label">Difficulty</div><div class="stat-value" id="difficultyDisplay">0</div><div class="stat-sub">current network difficulty</div></div>
      <div class="stat-card"><div class="stat-icon green"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg></div><div class="stat-label">Block Time</div><div class="stat-value" id="blockTimeDisplay">0s</div><div class="stat-sub">target interval</div></div>
      <div class="stat-card"><div class="stat-icon green"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></div><div class="stat-label">Peers</div><div class="stat-value" id="peerCount">0</div><div class="stat-sub" id="peerSub">connected</div></div>
      <div class="stat-card"><div class="stat-icon orange"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="7"></circle><polyline points="12 8 12 12 15 15"></polyline><path d="M2.5 18.5A5 5 0 0 1 8 22h8a5 5 0 0 0 5-5.5V12"></path></svg></div><div class="stat-label">Issued Supply</div><div class="stat-value" id="issuedDisplay">0</div><div class="stat-sub">/ 2.1B XODE</div><div class="progress-track"><div class="progress-fill" id="supplyProgress" style="width:0%"></div></div></div>
      <div class="stat-card"><div class="stat-icon red"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"></path></svg></div><div class="stat-label">Burned</div><div class="stat-value" id="burnedDisplay">0</div><div class="stat-sub">XODE destroyed</div></div>
      <div class="stat-card"><div class="stat-icon" style="background:rgba(59,130,246,0.1);color:#3b82f6"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg></div><div class="stat-label">Avg Block Time</div><div class="stat-value" id="avgBlockTimeDisplay">0s</div><div class="stat-sub">last 10 blocks</div></div>
      <div class="stat-card"><div class="stat-icon" style="background:rgba(236,72,153,0.1);color:#ec4899"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg></div><div class="stat-label">Global Online</div><div class="stat-value" id="globalOnlineDisplay">0</div><div class="stat-sub">total online users</div></div>
      <div class="stat-card"><div class="stat-icon" style="background:rgba(234,179,8,0.1);color:#eab308"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"></path></svg></div><div class="stat-label">POW Nodes</div><div class="stat-value" id="powNodesDisplay">0</div><div class="stat-sub">mining nodes</div></div>
      <div class="stat-card"><div class="stat-icon" style="background:rgba(16,185,129,0.1);color:#10b981"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"></path></svg></div><div class="stat-label">Hashrate</div><div class="stat-value" id="hashrateDisplay">0 h/s</div><div class="stat-sub" id="hashrateRatio">0% of network</div></div>
    </div>
    <div id="tab-connect" class="tab-content active">
      <div class="glass-card">
        <div class="section-header"><div class="section-title">Node Connection</div><div id="syncIndicator"></div></div>
        <div class="form-grid">
          <div class="form-group"><label>Node Address</label><input type="text" id="nodeHost" value="1.2.3.4" placeholder="IP or hostname"></div>
          <div class="form-group"><label>Port</label><input type="number" id="nodePort" value="5566"></div>
          <div class="form-group" style="display:flex;align-items:flex-end"><div style="color:#6b7a8f;font-size:13px;padding-bottom:14px">xode blockchain</div></div>
        </div>
        <div style="display:flex;gap:12px;margin-top:20px;flex-wrap:wrap">
          <button class="btn btn-primary" id="connectBtn" onclick="connect()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg> Connect</button>
          <button class="btn btn-danger" id="disconnectBtn" onclick="disconnect()" disabled><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path><line x1="12" y1="2" x2="12" y2="12"></line></svg> Disconnect</button>
          <button class="btn btn-secondary" onclick="syncChain()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg> Sync</button>
          <button class="btn btn-secondary" onclick="getStats()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg> Stats</button>
        </div>
      </div>
      <div class="glass-card">
        <div class="section-title">Supply Progress</div>
        <div class="progress-track" style="height:12px;margin-top:16px"><div class="progress-fill" id="supplyProgress2" style="width:0%"></div></div>
        <div style="display:flex;justify-content:space-between;margin-top:10px;font-size:13px;color:#6b7a8f"><span>0 XODE</span><span id="supplyPercent">0%</span><span>2,100,000,000 XODE</span></div>
      </div>
    </div>
    <div id="tab-transfer" class="tab-content">
      <div class="glass-card">
        <div class="section-title">Transfer XODE</div>
        <div class="form-group" style="margin-bottom:16px"><label>Target Address</label><input type="text" id="transferTo" placeholder="XODE0000000000000000" maxlength="20"></div>
        <div class="form-grid">
          <div class="form-group"><label>Amount (XODE)</label><input type="number" id="transferAmount" placeholder="100" step="0.01" min="0"></div>
          <div class="form-group"><label>Fee</label><input type="text" id="displayFee" value="1.00000000 XODE" disabled style="opacity:.6"></div>
          <div class="form-group"><label>Total</label><input type="text" id="displayTotal" value="0.00000000 XODE" disabled style="opacity:.6"></div>
        </div>
        <button class="btn btn-primary" id="sendBtn" onclick="sendTransfer()" disabled style="margin-top:20px"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13"></path><path d="M22 2l-7 20-4-9-9-4 20-7z"></path></svg> Send Transfer</button>
        <div id="transferResult" style="margin-top:20px"></div>
      </div>
    </div>
    <div id="tab-blocks" class="tab-content">
      <div class="glass-card">
        <div class="section-header"><div class="section-title">Blockchain Explorer</div><div style="display:flex;gap:8px"><button class="btn btn-secondary" onclick="syncChain()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg> Sync from Network</button><button class="btn btn-secondary" onclick="showLocalChain()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path><polyline points="17 21 17 13 7 13 7 21"></polyline><polyline points="7 3 7 8 15 8"></polyline></svg> Show Local Chain</button></div></div>
        <div style="display:grid;grid-template-columns:1fr auto;gap:12px;margin-bottom:20px">
          <div class="form-group" style="margin-bottom:0"><input type="text" id="searchQuery" placeholder="Search by Address / Block Hash / TX Hash / Block #" style="width:100%"></div>
          <button class="btn btn-primary" onclick="searchChain()" style="align-self:end"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Search</button>
        </div>
        <div id="searchResultInfo" style="margin-bottom:12px;font-size:13px;color:#6b7a8f;display:none"></div>
        <div id="blocksContainer"><div class="empty-state"><div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg></div><div>No blocks loaded yet</div><div style="font-size:13px;margin-top:8px;color:#4a5568">Connect and sync to view blocks</div></div></div>
      </div>
    </div>
    <div id="tab-history" class="tab-content">
      <div class="glass-card">
        <div class="section-header">
          <div class="section-title">Transaction History</div>
          <div style="display:flex;gap:8px">
            <button class="btn btn-secondary" onclick="rescanHistory()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg> Rescan Chain</button>
            <button class="btn btn-secondary" onclick="refreshHistory()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg> Refresh</button>
            <button class="btn btn-secondary" onclick="clearHistory()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg> Clear</button>
          </div>
        </div>

        <!-- Stats Cards -->
        <div class="stats-grid" style="margin-bottom:20px">
          <div class="stat-card">
            <div class="stat-icon" style="background:rgba(0,212,255,0.1);color:#00d4ff"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="7"></circle><polyline points="12 8 12 12 15 15"></polyline></svg></div>
            <div class="stat-label">Total Rewards</div>
            <div class="stat-value" id="statTotalReward" style="color:#00d4ff">0.00000000</div>
            <div class="stat-sub"><span id="statRewardCount">0</span> blocks</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon green"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg></div>
            <div class="stat-label">Total Received</div>
            <div class="stat-value" id="statTotalReceived" style="color:#22c55e">0.00000000</div>
            <div class="stat-sub"><span id="statReceivedCount">0</span> transfers</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon red"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg></div>
            <div class="stat-label">Total Sent</div>
            <div class="stat-value" id="statTotalSent" style="color:#ef4444">0.00000000</div>
            <div class="stat-sub"><span id="statSentCount">0</span> transfers</div>
          </div>

        </div>

        <!-- Pending Status Banner -->
        <div id="pendingStatusBanner" style="display:none;margin-bottom:16px;padding:12px 16px;background:rgba(0,0,0,0.2);border:1px solid rgba(255,255,255,0.06);border-radius:12px;font-size:13px">
          <span id="pendingStatusText" style="color:#f97316"></span>
        </div>

        <!-- Filter Tabs -->
        <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
          <button class="btn btn-secondary" id="filterAll" onclick="filterHistory('all')" style="font-size:12px;padding:8px 16px">All</button>
          <button class="btn btn-secondary" id="filterReward" onclick="filterHistory('reward')" style="font-size:12px;padding:8px 16px">Rewards</button>
          <button class="btn btn-secondary" id="filterIn" onclick="filterHistory('in')" style="font-size:12px;padding:8px 16px">Received</button>
          <button class="btn btn-secondary" id="filterOut" onclick="filterHistory('out')" style="font-size:12px;padding:8px 16px">Sent</button>
        </div>

        <div id="historyContainer">
          <div class="empty-state" style="padding:40px">
            <div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg></div>
            <div>No transactions yet</div>
            <div style="font-size:13px;margin-top:8px;color:#4a5568">Click "Rescan Chain" to load from blockchain</div>
          </div>
        </div>
      </div>
    </div>
    <div id="tab-wallet" class="tab-content">
      <div class="glass-card">
        <div class="section-title">Wallet Details</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px">
          <div class="form-group"><label>Address</label><input type="text" id="walletAddrDetail" readonly value="---"></div>
          <div class="form-group"><label>Public Key</label><input type="text" id="walletPubkeyDetail" readonly value="---"></div>
          <div class="form-group"><label>Balance</label><input type="text" id="walletBalanceDetail" readonly value="0 XODE"></div>
          <div class="form-group"><label>Nonce</label><input type="text" id="walletNonce" readonly value="0"></div>
          <div class="form-group"><label>Created</label><input type="text" id="walletCreated" readonly value="---"></div>
          <div class="form-group"><label>Wallet File</label><input type="text" id="walletFile" readonly value="---"></div>
        </div>
        <div style="margin-top:20px;display:flex;gap:12px;flex-wrap:wrap">
          <button class="btn btn-secondary" id="showPrivkeyBtn" onclick="toggleShowPrivateKey()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg> Show Private Key</button>
          <button class="btn btn-secondary" onclick="exportWallet()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg> Export wallet.dat</button>
        </div>
        <div id="privkeyDisplay" style="display:none;margin-top:16px;padding:16px;background:rgba(249,115,22,0.05);border:1px solid rgba(249,115,22,0.2);border-radius:12px">
          <div style="font-size:12px;color:#6b7a8f;margin-bottom:8px"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> Private Key (keep secret!)</div>
          <div style="font-family:monospace;font-size:12px;color:#f97316;word-break:break-all" id="privkeyValue"></div>
        </div>
      </div>
      <div class="danger-zone">
        <div class="danger-title"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> Danger Zone</div>
        <p style="font-size:13px;color:#6b7a8f;margin-bottom:16px">Creating a new wallet will overwrite your current wallet.dat. Make sure you have backed up your private key!</p>
        <button class="btn btn-danger" onclick="createNewWallet()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg> Create New Wallet</button>
      </div>
    </div>
    <div id="tab-logs" class="tab-content">
      <div class="glass-card">
        <div class="section-header"><div class="section-title">System Logs</div><button class="btn btn-secondary" onclick="clearLogs()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg> Clear</button></div>
        <div class="log-container" id="logContainer"><div class="empty-state" style="padding:40px"><div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></div><div>No logs yet</div></div></div>
      </div>
    </div>
    <div id="tab-rankings" class="tab-content">
      <div class="glass-card">
        <div class="section-header"><div class="section-title">Global Address Rankings</div><div style="display:flex;gap:8px"><button class="btn btn-secondary" onclick="refreshRankings()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg> Refresh</button></div></div>
        <div style="display:flex;gap:12px;margin-bottom:16px;align-items:center">
          <div style="font-size:13px;color:#6b7a8f">Total Addresses: <span id="totalRankedAddresses" style="color:#00d4ff;font-weight:700">0</span></div>
          <div style="font-size:13px;color:#6b7a8f">Your Rank: <span id="myRank" style="color:#a855f7;font-weight:700">-</span></div>
          <div style="font-size:13px;color:#6b7a8f">Your Balance: <span id="myRankBalance" style="color:#22c55e;font-weight:700">0.00000000</span> XODE</div>
        </div>
        <div id="rankingsContainer">
          <div class="empty-state" style="padding:40px">
            <div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20V10"></path><path d="M18 20V4"></path><path d="M6 20v-4"></path></svg></div>
            <div>Loading rankings...</div>
            <div style="font-size:13px;margin-top:8px;color:#4a5568">Connect and sync to view address rankings</div>
          </div>
        </div>
      </div>
    </div>
  </main>
</div>
<div class="toast-container" id="toastContainer"></div>
<script>
const particlesContainer=document.getElementById('particles');
for(let i=0;i<20;i++){const p=document.createElement('div');p.className='particle';const s=Math.random()*100+50;p.style.width=s+'px';p.style.height=s+'px';p.style.left=Math.random()*100+'%';p.style.top=Math.random()*100+'%';p.style.animationDelay=Math.random()*20+'s';p.style.animationDuration=(Math.random()*20+20)+'s';particlesContainer.appendChild(p);}
let currentTab='connect',pollInterval,privateKeyVisible=false,isDisconnecting=false;
function switchTab(tab,el){currentTab=tab;document.querySelectorAll('.nav-item').forEach(t=>t.classList.remove('active'));document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));if(el)el.classList.add('active');else{const items=document.querySelectorAll('.nav-item');for(let i=0;i<items.length;i++){if(items[i].getAttribute('onclick')&&items[i].getAttribute('onclick').indexOf(tab)!==-1){items[i].classList.add('active');break;}}}document.getElementById('tab-'+tab).classList.add('active');}
function showToast(msg,type='info'){const c=document.getElementById('toastContainer'),t=document.createElement('div');t.className='toast toast-'+type;t.textContent=msg;c.appendChild(t);setTimeout(()=>{t.style.animation='slideIn .4s cubic-bezier(0.16,1,0.3,1) reverse';setTimeout(()=>t.remove(),400)},4000);}
async function connect(){const host=document.getElementById('nodeHost').value,port=parseInt(document.getElementById('nodePort').value),btn=document.getElementById('connectBtn');btn.disabled=true;btn.textContent='⏳ Connecting...';try{const res=await fetch('/api/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,port})});const data=await res.json();if(data.success){showToast(data.message,'success');startPolling()}else{showToast(data.message,'error');btn.disabled=false;btn.textContent='🔗 Connect'}}catch(e){showToast('Failed: '+e.message,'error');btn.disabled=false;btn.textContent='🔗 Connect'}}
async function disconnect(){isDisconnecting=true;stopPolling();await fetch('/api/disconnect',{method:'POST'});showToast('Disconnected','info');updateUI({connected:false});isDisconnecting=false;}
async function syncChain(){const res=await fetch('/api/sync',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error');}
async function getStats(){const res=await fetch('/api/stats',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error');}
async function showLocalChain(){const res=await fetch('/api/local_chain');const data=await res.json();renderBlocks(data.chain);showToast('Loaded '+data.chain.length+' blocks','success');}
async function sendTransfer(){const to=document.getElementById('transferTo').value,amount=document.getElementById('transferAmount').value;const res=await fetch('/api/transfer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to,amount})});const data=await res.json();showToast(data.message,data.success?'success':'error');if(data.success){document.getElementById('transferTo').value='';document.getElementById('transferAmount').value='';}}
async function refreshHistory(){const res=await fetch('/api/history',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error');}
async function clearHistory(){await fetch('/api/clear_history',{method:'POST'});currentHistoryData=[];document.getElementById('historyContainer').innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg></div><div>History cleared</div></div>';document.getElementById('statTotalReward').textContent='0.00000000';document.getElementById('statRewardCount').textContent='0';document.getElementById('statTotalReceived').textContent='0.00000000';document.getElementById('statReceivedCount').textContent='0';document.getElementById('statTotalSent').textContent='0.00000000';document.getElementById('statSentCount').textContent='0';showToast('History cleared','info');}
async function clearLogs(){await fetch('/api/clear_logs',{method:'POST'});document.getElementById('logContainer').innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></div><div>Logs cleared</div></div>';showToast('Logs cleared','info');}
function toggleShowPrivateKey(){const display=document.getElementById('privkeyDisplay'),btn=document.getElementById('showPrivkeyBtn');if(display.style.display==='none'||display.style.display===''){display.style.display='block';btn.textContent='🔒 Hide Private Key';showPrivateKey();}else{display.style.display='none';btn.textContent='🔑 Show Private Key';privateKeyVisible=false;}}
async function showPrivateKey(){try{const res=await fetch('/api/wallet_info');const data=await res.json();if(data.private_key){document.getElementById('privkeyValue').textContent=data.private_key;privateKeyVisible=true;}else{showToast('Could not retrieve private key','error')}}catch(e){showToast('Error: '+e.message,'error')}}
async function exportWallet(){try{const res=await fetch('/api/export_wallet_dat');if(!res.ok){showToast('Export failed','error');return}const blob=await res.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='wallet.dat';a.click();URL.revokeObjectURL(url);showToast('wallet.dat exported!','success');}catch(e){showToast('Export error: '+e.message,'error')}}
async function createNewWallet(){if(!confirm('WARNING: This will overwrite your current wallet!\\nMake sure you have backed up your private key.\\n\\nContinue?'))return;const res=await fetch('/api/new_wallet',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error');if(data.success){setTimeout(()=>location.reload(),1000)}}
let currentHistoryFilter='all',currentHistoryData=[];
function filterHistory(filter){currentHistoryFilter=filter;document.querySelectorAll('#tab-history .btn-secondary').forEach(b=>{b.style.background='rgba(255,255,255,0.05)';b.style.color='#e0e6ed';b.style.borderColor='rgba(255,255,255,0.1)';});const activeBtn=document.getElementById('filter'+filter.charAt(0).toUpperCase()+filter.slice(1));if(activeBtn){activeBtn.style.background='linear-gradient(135deg,rgba(0,212,255,0.15),rgba(123,44,191,0.1))';activeBtn.style.color='#00d4ff';activeBtn.style.borderColor='rgba(0,212,255,0.2)';}renderHistoryList(currentHistoryData);}
async function rescanHistory(){const c=document.getElementById('historyContainer');c.innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-icon"><span class="spinner" style="width:32px;height:32px;border-width:3px"></span></div><div>Scanning blockchain...</div></div>';try{const res=await fetch('/api/rescan_history',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error');}catch(e){showToast('Rescan failed: '+e.message,'error');}}
function renderHistoryList(txs){const c=document.getElementById('historyContainer');if(!txs||txs.length===0){c.innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg></div><div>No transactions yet</div><div style="font-size:13px;margin-top:8px;color:#4a5568">Click "Rescan Chain" to load from blockchain</div></div>';return;}let filtered=txs;if(currentHistoryFilter!=='all'){filtered=txs.filter(tx=>{const t=tx.type||'transfer';const d=tx.direction||'';if(currentHistoryFilter==='reward')return t==='reward';if(currentHistoryFilter==='in')return d==='in';if(currentHistoryFilter==='out')return d==='out';return true;});}if(filtered.length===0){c.innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-icon">🔍</div><div>No '+currentHistoryFilter+' transactions</div></div>';return;}let html='';const currentHeight=parseInt(document.getElementById('blockHeightDisplay').textContent.replace(/,/g,''))||0;[...filtered].reverse().forEach(tx=>{const myAddr=document.getElementById('addressDisplay')?.textContent||'';const txType=tx.type||'transfer';const direction=tx.direction||'';const isReward=txType==='reward';const isSent=direction==='out';const isReceived=direction==='in'||isReward;let typeLabel,iconSvg,typeClass,amountColor;if(isReward){typeLabel=tx.is_producer_reward?'Producer Reward':'Block Reward';iconSvg='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="7"></circle><polyline points="12 8 12 12 15 15"></polyline></svg>';typeClass='reward';amountColor='#00d4ff';}else if(isSent){typeLabel='Sent';iconSvg='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>';typeClass='sent';amountColor='#ef4444';}else{typeLabel='Received';iconSvg='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>';typeClass='received';amountColor='#22c55e';}const counterparty=isSent?(tx.to||'N/A'):(isReward?'SYSTEM':(tx.from||'N/A'));const date=tx.timestamp?new Date(tx.timestamp*1000).toLocaleString():'Unknown';const amount=parseFloat(tx.amount||0).toFixed(8);const fee=tx.fee?parseFloat(tx.fee).toFixed(8):null;
            // Confirmation progress
            let confirmHtml='';
            const txBlock=tx.block_index;
            const required=isReward?30:6;
            if(txBlock!==undefined&&txBlock!==null&&currentHeight>=txBlock){
                const confs=Math.max(0,currentHeight-txBlock+1);
                const isMature=confs>=required;
                const pct=Math.min(100,Math.round((confs/required)*100));
                const statusColor=isMature?'#22c55e':isReward?'#f97316':'#00d4ff';
                const statusText=isMature?'✓ Confirmed':isReward?'⏳ Maturing ('+confs+'/'+required+')':'⏳ Confirming ('+confs+'/'+required+')';
                confirmHtml='<div style="margin-top:6px"><div style="display:flex;justify-content:space-between;align-items:center;font-size:10px;margin-bottom:3px"><span style="color:'+statusColor+'">'+statusText+'</span><span style="color:#4a5568">'+pct+'%</span></div><div style="width:100%;height:5px;background:rgba(0,0,0,0.3);border-radius:3px;overflow:hidden"><div style="width:'+pct+'%;height:100%;background:linear-gradient(90deg,'+statusColor+','+(isMature?'#16a34a':'#7c3aed')+');border-radius:3px;transition:width .3s"></div></div></div>';
            }else if(txBlock!==undefined&&txBlock!==null){
                confirmHtml='<div style="font-size:10px;color:#f97316;margin-top:6px">⏳ Pending (block not yet synced)</div>';
            }else{
                confirmHtml='<div style="font-size:10px;color:#f97316;margin-top:6px">⏳ Pending in mempool</div>';
            }
            // Extra info for rewards
            let extraInfo='';
            if(isReward){
                extraInfo='<div style="font-size:10px;color:#a855f7;margin-top:2px">Block #'+txBlock+' | Maturity: #'+(tx.maturity_block||txBlock+30)+'</div>';
            }
            const txHashStr=tx.tx_hash?'<div style="font-family:monospace;font-size:10px;color:#a855f7;margin-top:2px;word-break:break-all">'+(tx.tx_hash.length>64?'Hash: ':'TX: ')+tx.tx_hash.substring(0,20)+(tx.tx_hash.length>20?'...':'')+'</div>':'';
            const feeStr=fee&&parseFloat(fee)>0?' <span style="color:#f97316;font-size:11px">+'+fee+' fee</span>':'';
            const sign=isSent?'-':(isReward||isReceived?'+':'');
            html+='<div class="tx-item" style="grid-template-columns:auto 1fr auto;gap:14px;padding:14px 16px">';
            html+='<div class="tx-icon '+typeClass+'" style="width:40px;height:40px;border-radius:10px">'+iconSvg+'</div>';
            html+='<div class="tx-details" style="min-width:0">';
            html+='<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">';
            html+='<span class="tx-type" style="font-size:13px;font-weight:600">'+typeLabel+'</span>';
            if(isReward){html+='<span style="font-size:10px;color:#00d4ff;background:rgba(0,212,255,0.1);padding:2px 6px;border-radius:4px">REWARD</span>';}
            html+='</div>';
            html+='<div class="tx-addr" style="font-size:11px;margin-top:3px">'+counterparty+'</div>';
            html+=txHashStr;
            html+=extraInfo;
            html+=confirmHtml;
            html+='</div>';
            html+='<div class="tx-amount" style="text-align:right;min-width:120px">';
            html+='<div class="tx-amount-value" style="color:'+amountColor+';font-size:15px;font-weight:700">'+sign+amount+' XODE</div>';
            html+=feeStr;
            html+='<div style="font-size:10px;color:#4a5568;margin-top:4px">'+date+'</div>';
            html+='</div>';
            html+='</div>';
        });
        c.innerHTML=html;
}
function renderHistory(txs){currentHistoryData=txs||[];renderHistoryList(currentHistoryData);}
async function refreshRankings(){const c=document.getElementById('rankingsContainer');c.innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-icon"><span class="spinner" style="width:32px;height:32px;border-width:3px"></span></div><div>Loading rankings...</div></div>';try{const res=await fetch('/api/rankings');const data=await res.json();if(data.success){document.getElementById('totalRankedAddresses').textContent=data.total.toLocaleString();document.getElementById('myRank').textContent=data.my_rank>0?'#'+data.my_rank.toLocaleString():'-';document.getElementById('myRankBalance').textContent=parseFloat(data.my_balance).toFixed(8);renderRankings(data.rankings,data.my_address);}else{c.innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-icon">⚠</div><div>Failed to load rankings</div><div style="font-size:13px;margin-top:8px;color:#4a5568">'+(data.message||'Unknown error')+'</div></div>';}}catch(e){c.innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-icon">⚠</div><div>Error loading rankings</div><div style="font-size:13px;margin-top:8px;color:#4a5568">'+e.message+'</div></div>';}}
function renderRankings(rankings,myAddress){const c=document.getElementById('rankingsContainer');if(!rankings||rankings.length===0){c.innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20V10"></path><path d="M18 20V4"></path><path d="M6 20v-4"></path></svg></div><div>No addresses with balance</div><div style="font-size:13px;margin-top:8px;color:#4a5568">Sync chain to view rankings</div></div>';return;}let html='<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">';html+='<thead><tr style="text-align:left;font-size:11px;color:#6b7a8f;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid rgba(255,255,255,0.1)"><th style="padding:10px 12px;width:60px">Rank</th><th style="padding:10px 12px">Address</th><th style="padding:10px 12px;text-align:right">Balance (XODE)</th><th style="padding:10px 12px;text-align:right">Supply %</th></tr></thead><tbody>';const totalSupply=2100000000;rankings.forEach(item=>{const isMe=item.is_me;const pct=totalSupply?(item.balance/totalSupply*100).toFixed(6):'0.000000';const rankColor=item.rank===1?'#fbbf24':item.rank===2?'#9ca3af':item.rank===3?'#b45309':'#6b7a8f';const rowBg=isMe?'rgba(0,212,255,0.05)':'transparent';const rowBorder=isMe?'1px solid rgba(0,212,255,0.2)':'1px solid rgba(255,255,255,0.03)';html+='<tr class="rank-row" style="background:'+rowBg+';border-bottom:'+rowBorder+';transition:all .2s">';html+='<td style="padding:12px;font-weight:800;font-size:16px;color:'+rankColor+'">#'+item.rank+'</td>';html+='<td style="padding:12px;font-family:monospace;font-size:12px;word-break:break-all;color:'+(isMe?'#00d4ff':'#a5b4fc')+'">'+item.address+(isMe?' <span style="color:#00d4ff;font-size:10px;background:rgba(0,212,255,0.1);padding:2px 6px;border-radius:4px">YOU</span>':'')+'</td>';html+='<td style="padding:12px;text-align:right;font-weight:700;color:#00d4ff;font-size:14px">'+parseFloat(item.balance).toFixed(8)+'</td>';html+='<td style="padding:12px;text-align:right;font-size:12px;color:#6b7a8f">'+pct+'%</td>';html+='</tr>';});html+='</tbody></table></div>';c.innerHTML=html;}
async function searchChain(){const query=document.getElementById('searchQuery').value.trim();if(!query){showToast('Please enter a search query','warning');return;}const infoEl=document.getElementById('searchResultInfo');infoEl.style.display='block';infoEl.innerHTML='<span class="sync-badge"><span class="spinner"></span>Searching...</span>';try{const res=await fetch('/api/search',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query})});const data=await res.json();if(data.success){if(data.blocks&&data.blocks.length>0){infoEl.innerHTML='<span style="color:#22c55e">✓ Found '+data.blocks.length+' result(s) for "'+query+'"</span>';renderBlocks(data.blocks,true);}else{infoEl.innerHTML='<span style="color:#f97316">⚠ No results found for "'+query+'"</span>';document.getElementById('blocksContainer').innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-icon">🔍</div><div>No matching blocks or transactions</div><div style="font-size:13px;margin-top:8px;color:#4a5568">Try a different address, hash, or block number</div></div>';}}else{infoEl.innerHTML='<span style="color:#ef4444">✗ Search failed: '+(data.message||'Unknown error')+'</span>';}}catch(e){infoEl.innerHTML='<span style="color:#ef4444">✗ Search error: '+e.message+'</span>';}}
function renderBlocks(chain,isSearchResult){
const c=document.getElementById('blocksContainer');
if(!chain||chain.length===0){
c.innerHTML='<div class="empty-state"><div class="empty-state-icon">📦</div><div>No blocks loaded yet</div></div>';
return;
}
let html='';
const searchQuery=(document.getElementById('searchQuery')&&isSearchResult)?document.getElementById('searchQuery').value.trim().toLowerCase():'';
function hl(text){if(!searchQuery||!text)return String(text||'');const s=String(text).toLowerCase();const q=searchQuery;let idx=s.indexOf(q);if(idx===-1)return String(text);const orig=String(text);let out='';let last=0;while(idx!==-1){out+=orig.substring(last,idx)+'<mark style="background:rgba(0,212,255,0.3);color:#00d4ff;padding:1px 3px;border-radius:3px;font-weight:700">'+orig.substring(idx,idx+q.length)+'</mark>';last=idx+q.length;idx=s.indexOf(q,last);}out+=orig.substring(last);return out;}
[...chain].reverse().forEach(block=>{
const reward=block.reward||block.reward_tx||{},supply=block.supply||{},txs=block.transactions||[];
const date=new Date(block.timestamp*1000).toLocaleString();
const perUser=reward.per_user||reward.reward_per_user||0;

let rewardHtml='';
const recipients=reward.recipients||[];
if(recipients.length>0){
rewardHtml='<div style="background:rgba(0,212,255,0.04);border:1px solid rgba(0,212,255,0.1);border-radius:8px;padding:8px 10px;margin-bottom:8px">';
rewardHtml+='<div style="font-size:11px;color:#00d4ff;font-weight:600;margin-bottom:6px">🎁 Block Reward: '+perUser.toFixed(8)+' XODE x '+recipients.length+' users</div>';
rewardHtml+='<div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:4px;font-size:10px;font-family:monospace">';
recipients.forEach(r=>{
const addr=typeof r==='object'?r.address:r;
const amt=typeof r==='object'?parseFloat(r.amount||perUser).toFixed(8):parseFloat(perUser).toFixed(8);
rewardHtml+='<div style="background:rgba(0,0,0,0.2);padding:4px 6px;border-radius:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">';
rewardHtml+='<span style="color:#a5b4fc">'+hl(addr)+'</span> <span style="color:#00d4ff">'+amt+'</span>';
rewardHtml+='</div>';
});
rewardHtml+='</div></div>';
}

let txHtml='';
if(txs.length>0){
txHtml='<div style="background:rgba(0,0,0,0.15);border:1px solid rgba(255,255,255,0.05);border-radius:8px;padding:8px 10px;margin-bottom:8px">';
txHtml+='<div style="font-size:11px;color:#f97316;font-weight:600;margin-bottom:6px">📋 Transactions ('+txs.length+')</div>';
txHtml+='<table style="width:100%;font-size:11px;border-collapse:collapse">';
txHtml+='<tr style="color:#6b7a8f;font-size:10px;text-align:left"><th style="padding:3px 6px">Type</th><th style="padding:3px 6px">TX Hash</th><th style="padding:3px 6px">From</th><th style="padding:3px 6px">To</th><th style="padding:3px 6px;text-align:right">Amount</th><th style="padding:3px 6px;text-align:right">Fee</th></tr>';
txs.forEach(tx=>{
const txType=tx.type||'transfer';
const from=tx.from||'-';
const to=tx.to||'-';
const amt=parseFloat(tx.amount||0).toFixed(8);
const fee=parseFloat(tx.fee||0).toFixed(8);
txHtml+='<tr style="border-top:1px solid rgba(255,255,255,0.05)">';
txHtml+='<td style="padding:3px 6px;color:#00d4ff;font-size:10px">'+txType+'</td>';
const txHash=tx.tx_hash||'';
txHtml+='<td style="padding:3px 6px;font-family:monospace;font-size:10px;word-break:break-all;color:#a855f7">'+(txHash?hl(txHash):'-')+'</td>';
txHtml+='<td style="padding:3px 6px;font-family:monospace;font-size:10px;word-break:break-all;color:#a5b4fc">'+hl(from)+'</td>';
txHtml+='<td style="padding:3px 6px;font-family:monospace;font-size:10px;word-break:break-all;color:#a5b4fc">'+hl(to)+'</td>';
txHtml+='<td style="padding:3px 6px;text-align:right;color:#00d4ff;font-weight:600;font-size:10px">'+amt+'</td>';
txHtml+='<td style="padding:3px 6px;text-align:right;color:#f97316;font-size:10px">'+fee+'</td>';
txHtml+='</tr>';
});
txHtml+='</table></div>';
}

html+='<div class="block-card" style="padding:12px;margin-bottom:8px">';
html+='<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">';
html+='<span style="font-size:16px;font-weight:800;color:#00d4ff">#'+block.index+'</span>';
html+='<span style="font-family:monospace;font-size:10px;color:#4a5568">'+hl(block.hash)+'</span>';
html+='</div>';

html+='<div style="font-size:10px;font-family:monospace;color:#4a5568;margin-bottom:8px;line-height:1.6">';
html+='<div><span style="color:#6b7a8f">Hash:</span> <span style="color:#00d4ff">'+hl(block.hash)+'</span></div>';
html+='<div><span style="color:#6b7a8f">Prev:</span> <span style="color:#a855f7">'+hl(block.previous_hash||'Genesis')+'</span></div>';
html+='</div>';

html+='<div style="display:flex;gap:14px;font-size:11px;color:#6b7a8f;flex-wrap:wrap;margin-bottom:8px">';
html+='<span>⏰ '+date+'</span>';
if(supply.issued){html+='<span>📊 '+parseFloat(supply.issued)+'</span>';}
if(supply.burned_total||supply.burned_total===0){html+='<span>🔥 Burned: '+parseFloat(supply.burned_total||0)+'</span>';}
html+='<span>👥 '+(reward.online_count||0)+' online</span>';
html+='</div>';

html+=rewardHtml;
html+=txHtml;

html+='</div>';
});
c.innerHTML=html;
}
function updateUI(state){const statusEl=document.getElementById('connectionStatus'),statusText=document.getElementById('statusText'),connectBtn=document.getElementById('connectBtn'),disconnectBtn=document.getElementById('disconnectBtn'),sendBtn=document.getElementById('sendBtn');const connected=state.connected;if(connected){statusEl.className='status-pill connected';statusText.textContent='Connected ('+state.connected_nodes+' nodes)';connectBtn.disabled=true;connectBtn.textContent='✅ Connected';disconnectBtn.disabled=false;sendBtn.disabled=false;}else{statusEl.className='status-pill disconnected';statusText.textContent='Disconnected';connectBtn.disabled=false;connectBtn.textContent='🔗 Connect';disconnectBtn.disabled=true;sendBtn.disabled=true;}if(state.block_height!==undefined)document.getElementById('blockHeightDisplay').textContent=state.block_height.toLocaleString();if(state.total_issued!==undefined){document.getElementById('issuedDisplay').textContent=parseFloat(state.total_issued).toFixed(8);const pct=state.total_supply?(state.total_issued/state.total_supply*100).toFixed(4):0;document.getElementById('supplyProgress').style.width=pct+'%';document.getElementById('supplyProgress2').style.width=pct+'%';document.getElementById('supplyPercent').textContent=pct+'%';}if(state.burned_total!==undefined)document.getElementById('burnedDisplay').textContent=parseFloat(state.burned_total).toFixed(8);if(state.address){
    document.getElementById('walletAddrDetail').value=state.address;
    document.getElementById('addressDisplay').textContent=state.address;
}if(state.public_key){document.getElementById('walletPubkeyDetail').value=state.public_key;}if(state.block_time)document.getElementById('blockTime').textContent=state.block_time+'s';
        if(state.difficulty!==undefined)document.getElementById('difficultyDisplay').textContent=state.difficulty.toFixed(4);
        if(state.block_time!==undefined)document.getElementById('blockTimeDisplay').textContent=state.block_time+'s';if(state.block_reward)document.getElementById('blockReward').textContent=parseFloat(state.block_reward).toFixed(8)+' XODE';if(state.transfer_fee)document.getElementById('transferFee').textContent=parseFloat(state.transfer_fee).toFixed(8)+' XODE';if(state.pending_tx!==undefined)document.getElementById('pendingTx').textContent=state.pending_tx;
        if(state.avg_block_time!==undefined)document.getElementById('avgBlockTimeDisplay').textContent=state.avg_block_time+'s';
        if(state.global_online!==undefined)document.getElementById('globalOnlineDisplay').textContent=state.global_online.toLocaleString();
        if(state.producer_count!==undefined)document.getElementById('powNodesDisplay').textContent=state.producer_count.toLocaleString();
        if(state.local_hashrate!==undefined)document.getElementById('hashrateDisplay').textContent=state.local_hashrate.toLocaleString()+' h/s';
        if(state.hashrate_ratio!==undefined&&state.network_hashrate!==undefined)document.getElementById('hashrateRatio').textContent=state.hashrate_ratio+'% of network ('+state.network_hashrate.toLocaleString()+' h/s)';
        if(state.wallet_file)document.getElementById('walletFile').value=state.wallet_file;if(state.wallet_created)document.getElementById('walletCreated').value=new Date(state.wallet_created*1000).toLocaleString();if(state.balance!==undefined){
    document.getElementById('walletBalanceDetail').value=parseFloat(state.balance).toFixed(8)+' XODE';
    document.getElementById('walletBalanceDisplay').textContent=parseFloat(state.balance).toFixed(8);
    document.getElementById('availableBalanceDisplay').textContent=parseFloat(state.available_balance||state.balance).toFixed(2);
    document.getElementById('lockedBalanceDisplay').textContent=parseFloat(state.locked_balance||0).toFixed(2);
}if(state.nonce!==undefined)document.getElementById('walletNonce').value=state.nonce;if(state.connected_nodes!==undefined){document.getElementById('peerCount').textContent=state.connected_nodes;document.getElementById('peerSub').textContent=state.connected_nodes===1?'connected':'connected';}const syncEl=document.getElementById('syncStatus'),syncInd=document.getElementById('syncIndicator');if(state.syncing){syncEl.innerHTML='<span class="sync-badge"><span class="spinner"></span>Syncing...</span>';syncInd.innerHTML='<span class="sync-badge"><span class="spinner"></span>Syncing '+state.sync_progress+'%</span>';}else if(state.chain_length&&state.block_height>state.local_height){syncEl.innerHTML='<span style="color:#f97316;font-size:12px">Local: #'+state.local_height+' / #'+state.block_height+'</span>';syncInd.innerHTML='';}else{syncEl.textContent='Synced';syncInd.innerHTML='';}if(state.logs&&state.logs.length>0){const logContainer=document.getElementById('logContainer');let html='';state.logs.forEach(log=>{const levelClass=log.level==='error'?'log-error':log.level==='success'?'log-success':log.level==='warning'?'log-warning':'log-info';html+='<div class="log-entry"><span class="log-time">'+log.time+'</span><span class="'+levelClass+'">'+log.msg+'</span></div>';});logContainer.innerHTML=html;logContainer.scrollTop=logContainer.scrollHeight;}if(state.transfer_result){const resultEl=document.getElementById('transferResult');if(state.transfer_result.success){resultEl.innerHTML='<div style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);padding:16px;border-radius:12px;color:#22c55e;"><strong><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> Transfer Success</strong><br>Sent '+state.transfer_result.amount+' XODE to '+state.transfer_result.to+'<br>Fee: '+(state.transfer_result.fee||0)+' XODE | Balance: '+(state.transfer_result.balance||0)+' XODE</div>';}else{resultEl.innerHTML='<div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);padding:16px;border-radius:12px;color:#ef4444;"><strong><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg> Transfer Failed</strong><br>'+(state.transfer_result.error||'Unknown error')+'</div>';}}if(state.chain){if(!window._lastChainLen||window._lastChainLen!==state.chain.length){window._lastChainLen=state.chain.length;renderBlocks(state.chain);}}// transaction_history kept for backward compat, address_history is primary        
        
        // Auto-load rankings when on rankings tab
        if(currentTab==='rankings'&&document.getElementById('rankingsContainer').querySelector('.empty-state')){refreshRankings();}
        // Update history stats
        if(state.address_stats){
            const s=state.address_stats;
            document.getElementById('statTotalReward').textContent=parseFloat(s.total_reward).toFixed(8);
            document.getElementById('statRewardCount').textContent=s.reward_count;
            document.getElementById('statTotalReceived').textContent=parseFloat(s.total_received).toFixed(8);
            document.getElementById('statReceivedCount').textContent=s.received_count;
            document.getElementById('statTotalSent').textContent=parseFloat(s.total_sent).toFixed(8);
            document.getElementById('statSentCount').textContent=s.sent_count;
        }
        // Update pending status banner
        const banner=document.getElementById('pendingStatusBanner');
        const bannerText=document.getElementById('pendingStatusText');
        if(state.address_stats){
            const s=state.address_stats;
            const parts=[];
            if(s.pending_rewards>0)parts.push(s.pending_rewards+' reward'+(s.pending_rewards>1?'s':'')+' maturing');
            if(s.pending_transfers_in>0)parts.push(s.pending_transfers_in+' transfer'+(s.pending_transfers_in>1?'s':'')+' confirming');
            if(parts.length>0){
                banner.style.display='block';
                bannerText.textContent='⏳ '+parts.join(' | ');
            }else{
                banner.style.display='none';
            }
        }
        // Update address history display
        if(state.address_history){
            renderHistory(state.address_history);
        }
}
async function pollState(){if(isDisconnecting)return;try{const res=await fetch('/api/state');if(!res.ok)throw new Error('HTTP '+res.status);const state=await res.json();if(isDisconnecting)return;updateUI(state);}catch(e){console.error('Poll error:',e);if(isDisconnecting)return;updateUI({connected:false,logs:[{time:new Date().toLocaleTimeString(),msg:'Connection lost: '+e.message,level:'error'}]});}}
function startPolling(){if(pollInterval)clearInterval(pollInterval);pollInterval=setInterval(pollState,1000);pollState();}
function stopPolling(){if(pollInterval){clearInterval(pollInterval);pollInterval=null;}}
document.getElementById('transferAmount').addEventListener('input',function(){const amount=parseFloat(this.value)||0;const fee=parseFloat(document.getElementById('displayFee').textContent)||1;document.getElementById('displayTotal').value=(amount+fee).toFixed(8)+' XODE';});
document.getElementById('searchQuery').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();searchChain();}});
pollState();startPolling();
</script>
</body>
</html>
'''


# ============ API Handler ============
class APIHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_error(self, code, message=None):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        err_msg = message or self.responses.get(code, ('Error',))[0]
        self.wfile.write(json.dumps({"error": err_msg, "code": code}).encode('utf-8'))

    def do_GET(self):
        node = getattr(self.server, 'xode_node', None)
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))
        elif self.path == '/api/state':
            if not node:
                self.send_json({"connected": False, "error": "Node not ready"})
                return
            self.send_json(node.get_state())
        elif self.path == '/api/local_chain':
            if not node:
                self.send_json({"chain": []})
                return
            self.send_json({"chain": [b.to_dict() for b in node.chain]})
        elif self.path == '/api/rankings':
            if not node:
                self.send_json({"success": False, "message": "Node not ready"})
                return
            rankings = node.get_rankings()
            self.send_json({"success": True, **rankings})
        elif self.path == '/api/wallet_info':
            if not node:
                self.send_json({"error": "Node not ready"})
                return
            info = {
                "address": node.wallet.address,
                "public_key": node.wallet.public_key,
                "balance": from_atomic(node.balances.get(node.wallet.address, 0)),
                "created_at": node.wallet.created_at,
                "private_key": node.wallet.private_key,
                "nonce": node.address_nonces.get(node.wallet.address, -1),
                "version": node.wallet.version
            }
            self.send_json(info)
        elif self.path == '/api/export_wallet_dat':
            if os.path.exists(WALLET_FILE):
                try:
                    with open(WALLET_FILE, 'rb') as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Disposition', 'attachment; filename="wallet.dat"')
                    self.send_header('Content-Length', str(len(data)))
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(data)
                except Exception as e:
                    self.send_json({"success": False, "message": f"Export failed: {str(e)}"})
            else:
                self.send_json({"success": False, "message": "wallet.dat not found"})
        else:
            self.send_error(404)

    def do_POST(self):
        node = getattr(self.server, 'xode_node', None)
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}

        if self.path == '/api/connect':
            if not node:
                self.send_json({"success": False, "message": "Node not ready"})
                return
            host = data.get('host')
            port = data.get('port')
            if not host or not port:
                self.send_json({"success": False, "message": "Missing host or port"})
                return
            success = node._connect_to_peer(host, port)
            msg = f"Connected to {host}:{port}" if success else f"Failed to connect to {host}:{port}"
            self.send_json({"success": success, "message": msg})
        elif self.path == '/api/disconnect':
            if node:
                node.disconnect_all_peers()
            self.send_json({"success": True, "message": "Disconnected from all peers"})
        elif self.path == '/api/sync':
            if not node:
                self.send_json({"success": False, "message": "Node not ready"})
                return
            if not node.peer_sockets:
                self.send_json({"success": False, "message": "Not connected to any peers"})
                return
            threading.Thread(target=node._sync_chain_from_peers, daemon=True).start()
            self.send_json({"success": True, "message": "Sync started"})
        elif self.path == '/api/stats':
            if not node:
                self.send_json({"success": False, "message": "Node not ready"})
                return
            if not node.peer_sockets:
                self.send_json({"success": False, "message": "Not connected to any peers"})
                return
            node._broadcast_to_peers({"type": "get_stats"})
            self.send_json({"success": True, "message": "Stats requested"})
        elif self.path == '/api/transfer':
            if not node:
                self.send_json({"success": False, "message": "Node not ready"})
                return
            success, message = node.node_transfer(data.get('to'), data.get('amount'))
            self.send_json({"success": success, "message": message})
        elif self.path == '/api/clear_logs':
            if node:
                node.logs = []
                node.transfer_result = None
                node.balance_update = None
            self.send_json({"success": True})
        elif self.path == '/api/new_wallet':
            if not node:
                self.send_json({"success": False, "message": "Node not ready"})
                return
            node.wallet.create_new()
            self.send_json({"success": True, "message": f"New wallet: {node.wallet.address}"})
        elif self.path == '/api/history':
            if not node:
                self.send_json({"success": False, "message": "Node not ready"})
                return
            tx_count = len(node.transaction_history.get(node.wallet.address, []))
            self.send_json({"success": True, "message": f"{tx_count} transactions"})
        elif self.path == '/api/clear_history':
            if node:
                addr = node.wallet.address
                if addr in node.transaction_history:
                    node.transaction_history[addr] = []
            self.send_json({"success": True})
        elif self.path == '/api/search':
            if not node:
                self.send_json({"success": False, "message": "Node not ready"})
                return
            query = data.get('query', '').strip()
            if not query:
                self.send_json({"success": False, "message": "Empty query"})
                return
            results = node.search_chain(query)
            self.send_json({"success": True, "blocks": results, "count": len(results)})
        elif self.path == '/api/rankings':
            if not node:
                self.send_json({"success": False, "message": "Node not ready"})
                return
            limit = data.get('limit', 100)
            rankings = node.get_rankings(limit=limit)
            self.send_json({"success": True, **rankings})
        elif self.path == '/api/rescan_history':
            if not node:
                self.send_json({"success": False, "message": "Node not ready"})
                return
            history = node.scan_address_history()
            stats = node.get_address_stats()
            self.send_json({
                "success": True,
                "message": f"Scanned {len(history)} transactions from blockchain",
                "count": len(history),
                "stats": stats
            })
        else:
            self.send_error(404)

    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()


class ReuseAddrServer(http.server.HTTPServer):
    allow_reuse_address = True
    allow_reuse_port = True



class XodeNode:
    TOTAL_SUPPLY = 2100000000
    BLOCK_TIME = 120
    BLOCK_REWARD = 1000
    TRANSFER_FEE = 1
    INITIAL_DIFFICULTY = 24.0
    DIFFICULTY_ADJUSTMENT_INTERVAL = 10

    def __init__(self, host='0.0.0.0', port=5566, is_producer=False, peer_addrs=None, announce_ip=None):
        self.host = host
        self.port = port
        self.announce_ip = announce_ip
        self.clients = {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.lock = threading.RLock()
        self.chain_lock = threading.RLock()
        self.running = True
        self.heartbeat_interval = 30
        self.timeout = 300
        self.chain = []
        self.balances = {}
        self.pending_rewards = {}
        self.pending_transfers = {}
        self.total_issued = 0
        self.pending_transactions = {}
        self.transaction_history = {}
        self.address_nonces = {}
        self.last_connect_time = {}
        self.daily_transfer_stats = {}
        self.ip_bindings = {}
        self.broadcasted_tx_hashes = set()
        self.address_first_seen_block = {}
        self.load_data()

        self.wallet = ServerWallet()
        self.server_address = self.wallet.address
        self.server_public_key = self.wallet.public_key
        self.server_private_key = self.wallet.private_key
        self.node_id = self.server_address

        self.address_history = []
        self.load_address_history()

        self.is_producer = is_producer
        self.peer_addrs = peer_addrs or []
        self.peer_sockets = {}
        self.all_online_users = {}
        self.ONLINE_PROOF_INTERVAL = 300
        self.ONLINE_PROOF_VALIDITY = 600
        self.MIN_REWARD_BALANCE = 0
        self.online_proofs = {}
        self.peer_timestamps = {}
        self.max_time_offset = 30
        self.peer_lock = threading.Lock()
        self.local_hashrate = 0
        self.peer_hashrates = {}
        self.network_hashrate = 0
        self._peer_reconnect_interval = 30
        self._peer_heartbeat_interval = 25

        self.orphan_blocks = {}
        self.syncing = False
        self.sync_peer = None
        self.headers_synced = False
        self.block_inventory = set()
        self.pending_block_requests = set()
        self.sync_start_time = 0
        self.last_block_time = 0
        self.best_known_height = -1
        self.sync_lock = threading.RLock()
        self.sync_block_queue = []
        self.sync_peer = None

        self.peers_file = "xode_peers.json"
        self.known_peers = {}
        self._load_known_peers()

        self.node_nonce = secrets.token_hex(8)
        print(f"[P2P] 节点 nonce: {self.node_nonce}", flush=True)
        self._load_seed_peers()
        print("节点地址: " + self.server_address, flush=True)
        print("公钥: " + self.server_public_key[:32] + "...", flush=True)

        if not self.chain:
            self.load_data()

        if self.chain:
            self._validate_and_repair_chain()
            for block in self.chain:
                self.block_inventory.add(block.hash)
                self.block_inventory.add(block.previous_hash)

        if not self.chain:
            if not self.peer_addrs:
                self.create_genesis_block()
            else:
                print("同步链", flush=True)
        else:
            print("已有区块链，高度: #" + str(len(self.chain) - 1), flush=True)

        if self.server_address not in self.balances:
            self.balances[self.server_address] = 0

        # Web UI state attributes
        self.logs = []
        self.transfer_result = None
        self.balance_update = None

        # Node startup timestamp for warmup protection
        self.node_start_time = time.time()

    def save_data(self, snapshot=None):
        try:
            if snapshot is None:
                with self.lock:
                    snapshot = {
                        "chain": [block.to_dict() for block in self.chain],
                        "balances": self.balances.copy(),
                        "total_issued": self.total_issued,
                        "transaction_history": {k: v[:] for k, v in self.transaction_history.items()},
                        "address_nonces": self.address_nonces.copy(),
                        "ip_bindings": {k: v.copy() for k, v in self.ip_bindings.items()},
                        "address_first_seen_block": self.address_first_seen_block.copy(),
                        "daily_transfer_stats": {k: v.copy() for k, v in self.daily_transfer_stats.items()},
                        "pending_rewards": {k: v[:] for k, v in self.pending_rewards.items()},
                        "pending_transfers": {k: v[:] for k, v in self.pending_transfers.items()},
                        "pending_transactions": list(self.pending_transactions.values()),
                        "saved_at": time.time(),
                        "version": "xode"
                    }
            if _save_json_data(snapshot):
                print("数据已保存到 JSON", flush=True)
        except Exception as e:
            print("保存数据失败: " + str(e), flush=True)

    def load_data(self):
        try:
            data = _load_json_data()
            if data is None:
                print("创建新的区块链", flush=True)
                return

            self.chain = [Block.from_dict(b) for b in data.get("chain", [])]
            self.balances = data.get("balances", {})
            loaded_total_issued = data.get("total_issued", 0)
            saved_version = data.get("version", "")
            if "7.0" in str(saved_version) or "6.9" in str(saved_version) or "7.1" in str(saved_version):
                self.total_issued = int(loaded_total_issued)
            elif 0 < loaded_total_issued < self.TOTAL_SUPPLY:
                self.total_issued = to_atomic(loaded_total_issued)
            else:
                self.total_issued = int(loaded_total_issued)
            self.transaction_history = data.get("transaction_history", {})
            self.address_nonces = data.get("address_nonces", {})
            self.ip_bindings = data.get("ip_bindings", {})
            self.address_first_seen_block = data.get("address_first_seen_block", {})
            self.daily_transfer_stats = data.get("daily_transfer_stats", {})
            self.pending_rewards = data.get("pending_rewards", {})
            self.pending_transfers = data.get("pending_transfers", {})

            mempool_txs = data.get("pending_transactions", [])
            self.pending_transactions = {tx["tx_hash"]: tx for tx in mempool_txs if "tx_hash" in tx}

            print("数据已加载", flush=True)
            print("  区块数: " + str(len(self.chain)), flush=True)
            print("  已发行: " + format_amount(self.total_issued) + " XODE", flush=True)
            print("  用户余额记录: " + str(len(self.balances)) + " 条", flush=True)
            print("  IP绑定记录: " + str(len(self.ip_bindings)) + " 条", flush=True)
            print("  内存池交易: " + str(len(self.pending_transactions)) + " 笔", flush=True)

            self._recalc_total_issued_from_chain()
        except Exception as e:
            print("加载数据失败: " + str(e), flush=True)
            print("创建新的区块链", flush=True)

    def _validate_and_repair_chain(self):
        if len(self.chain) <= 1:
            return
        print("链验证", flush=True)
        broken_at = None
        for i in range(1, len(self.chain)):
            expected_prev = self.chain[i-1].hash
            actual_prev = self.chain[i].previous_hash
            if actual_prev != expected_prev:
                print(f"[链验证] 断裂发现: Block #{i} previous_hash 不匹配!", flush=True)
                print(f"  期望: {expected_prev}", flush=True)
                print(f"  实际: {actual_prev}", flush=True)
                broken_at = i
                break
            block = self.chain[i]
            hash_int = int(block.hash, 16)
            target = difficulty_to_target(block.difficulty)
            if hash_int >= target:
                print(f"[链验证] Block #{i} POW 验证失败! hash={block.hash}, difficulty={block.difficulty}", flush=True)
                broken_at = i
                break
            if block.hash != block.calculate_hash():
                print(f"[链验证] Block #{i} 哈希计算不匹配!", flush=True)
                broken_at = i
                break
            valid_ts, ts_err = self._validate_block_timestamp(block.timestamp, block_index=i)
            if not valid_ts:
                print(f"[链验证] Block #{i} 时间戳验证失败: {ts_err}", flush=True)
                broken_at = i
                break
        if broken_at is not None:
            print(f"[链验证] 链在 #{broken_at} 断裂！节点将停止运行。", flush=True)
            print(f"[链验证] 请手动检查数据文件: {DATA_FILE}", flush=True)
            self.running = False
            raise RuntimeError(f"Blockchain broken at block #{broken_at}. Node stopped for manual inspection.")
        else:
            print("[链验证] 链完整性验证通过，无断裂", flush=True)

    def is_valid_xode_address(self, address):
        if not address or not isinstance(address, str):
            return False
        if not address.startswith("XODE") or len(address) != 20:
            return False
        if address == BURN_ADDRESS:
            return True
        base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        addr_part = address[4:]
        for c in addr_part:
            if c not in base58_chars:
                return False
        return True

    def create_genesis_block(self):
        if BURN_ADDRESS not in self.balances:
            self.balances[BURN_ADDRESS] = 0
        genesis_reward = self.BLOCK_REWARD
        genesis_reward_atomic = to_atomic(genesis_reward)
        self.balances[BURN_ADDRESS] = self.balances.get(BURN_ADDRESS, 0) + genesis_reward_atomic
        self.total_issued = genesis_reward_atomic
        genesis = Block(
            index=0,
            timestamp=0,
            previous_hash="0" * 64,
            reward_tx={
                "total": genesis_reward,
                "online_count": 0,
                "ineligible_count": 0,
                "producer_node": self.server_address,
                "producer_eligible": False,
                "producer_reward": 0.0,
                "producer_reward_atomic": 0,
                "reward_per_user": 0.0,
                "reward_per_user_atomic": 0,
                "burned": genesis_reward,
                "burned_atomic": genesis_reward_atomic,
                "burn_address": BURN_ADDRESS,
                "recipients": [
                    {
                        "address": BURN_ADDRESS,
                        "amount": genesis_reward,
                        "amount_atomic": genesis_reward_atomic
                    }
                ]
            },
            transactions=[],
            nonce=0,
            difficulty=self.INITIAL_DIFFICULTY
        )
        self.chain.append(genesis)
        self.block_inventory.add(genesis.hash)
        print("[创世区块] #" + str(genesis.index) + " | 哈希: " + genesis.hash, flush=True)
        print("[创世区块] 创世奖励 " + format_amount(genesis_reward_atomic) + " XODE 已销毁至 " + BURN_ADDRESS, flush=True)
        self.save_data()

    def get_latest_block(self):
        return self.chain[-1]

    def get_online_users(self):
        with self.lock:
            return [
                {"address": info["address"], "socket": sock}
                for sock, info in self.clients.items()
            ]

    def get_burned_amount(self):
        return self.balances.get(BURN_ADDRESS, 0)

    def _get_median_peer_time(self):
        with self.peer_lock:
            times = [info.get("last_pong_time", time.time())
                     for info in self.peer_sockets.values()]
        if not times:
            return time.time()
        times.sort()
        return times[len(times) // 2]

    def get_median_time_past(self, block_index=None):
        if block_index is None:
            block_index = len(self.chain) - 1
        start = max(0, block_index - 10)
        timestamps = []
        for i in range(start, block_index + 1):
            if i < len(self.chain):
                timestamps.append(self.chain[i].timestamp)
        if not timestamps:
            return 0
        timestamps.sort()
        mid = len(timestamps) // 2
        if len(timestamps) % 2 == 0:
            return (timestamps[mid - 1] + timestamps[mid]) // 2
        return timestamps[mid]


    def _validate_block_timestamp(self, block_timestamp, block_index=None):
        if block_index is not None and block_index <= 0:
            return True, None
        if not self.chain:
            return True, None
        if block_index is None:
            block_index = len(self.chain)
        mtp = self.get_median_time_past(block_index - 1)
        if block_timestamp <= mtp:
            return False, f"区块时间戳 {block_timestamp} 必须大于 MTP {mtp}"
        now = time.time()
        if block_timestamp > now + 7200:
            return False, f"区块时间戳来自未来（超过2小时）"
        return True, None

    def get_spendable_balance(self, address):
        total_balance = self.balances.get(address, 0)
        current_height = len(self.chain) - 1
        locked = 0
    
        for reward in self.pending_rewards.get(address, []):
            try:
                maturity = reward.get("maturity_block", 0)
                amount = int(reward.get("amount", 0))
                if current_height < maturity and amount > 0:
                    locked += amount
            except (TypeError, ValueError):
                continue
    
        for transfer in self.pending_transfers.get(address, []):
            try:
                maturity = transfer.get("maturity_block", 0)
                amount = int(transfer.get("amount", 0))
                if current_height < maturity and amount > 0:
                    locked += amount
            except (TypeError, ValueError):
                continue
    
        for tx in self.pending_transactions.values():
            if tx.get("from") == address and tx.get("status") == "pending":
                try:
                    amount = int(tx.get("amount_atomic", 0))
                    fee = int(tx.get("fee_atomic", 0))
                    if amount > 0 or fee > 0:
                        locked += amount + fee
                except (TypeError, ValueError):
                    continue
    
        locked = min(locked, total_balance)
        available = total_balance - locked
        return max(0, available)

    def _cleanup_pending_rewards(self):
        current_height = len(self.chain) - 1
        for addr in list(self.pending_rewards.keys()):
            self.pending_rewards[addr] = [
                r for r in self.pending_rewards[addr]
                if current_height < r.get("maturity_block", 0)
            ]
            if not self.pending_rewards[addr]:
                del self.pending_rewards[addr]

    def _cleanup_pending_transfers(self):
        current_height = len(self.chain) - 1
        for addr in list(self.pending_transfers.keys()):
            self.pending_transfers[addr] = [
                t for t in self.pending_transfers[addr]
                if current_height < t.get("maturity_block", 0)
            ]
            if not self.pending_transfers[addr]:
                del self.pending_transfers[addr]

    def is_address_eligible_for_reward(self, address):
        first_seen = self.address_first_seen_block.get(address)
        if first_seen is None:
            return False
        current_height = len(self.chain) - 1
        return (current_height - first_seen) >= BLOCKS_BEFORE_REWARD

    def add_to_mempool(self, from_addr, to_addr, amount, signature=None, public_key=None,
                       tx_timestamp=None, tx_nonce=None, is_forwarded=False):
        if not public_key:
            return False, "缺少公钥"
        if not signature:
            return False, "缺少交易签名"
        if tx_nonce is None:
            return False, "缺少交易 nonce"

        if not verify_public_key_address(public_key, from_addr):
            return False, "公钥与地址不匹配"
        if not self.is_valid_xode_address(to_addr):
            return False, "目标地址格式无效"
        if from_addr == to_addr:
            return False, "不能转账给自己"

        atomic_amount = to_atomic(amount)
        if atomic_amount <= 0:
            return False, "转账金额必须大于0"
        if atomic_amount > MAX_TRANSFER_AMOUNT:
            max_display = format_amount(MAX_TRANSFER_AMOUNT)
            return False, f"单笔转账金额超过限制，最大允许 {max_display} XODE"

        atomic_fee = to_atomic(self.TRANSFER_FEE)
        total_needed = atomic_amount + atomic_fee

        message = build_sign_message(from_addr, to_addr, amount, tx_nonce, tx_timestamp)
        if not verify_signature(public_key, message, signature, timestamp=tx_timestamp):
            return False, "交易签名验证失败"

        with self.lock:
            last_nonce = self.address_nonces.get(from_addr, -1)
            if tx_nonce <= last_nonce:
                return False, f"交易 nonce 无效: {tx_nonce} (已使用: {last_nonce})，请勿重放交易"

            from_balance = self.get_spendable_balance(from_addr)
            if from_balance < total_needed:
                display_needed = format_amount(total_needed)
                display_fee = format_amount(atomic_fee)
                total_bal = self.balances.get(from_addr, 0)
                locked = total_bal - from_balance
                if locked > 0:
                    return False, f"可用余额不足，需要 {display_needed} XODE (含手续费 {display_fee} XODE)，您有 {format_amount(locked)} XODE 区块奖励尚未成熟（需 {REWARD_CONFIRMATIONS} 个确认）"
                return False, f"余额不足，需要 {display_needed} XODE (含手续费 {display_fee} XODE)"

            today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            stats = self.daily_transfer_stats.get(from_addr, {"count": 0, "amount": 0, "date": today})
            if stats.get("date") != today:
                stats = {"count": 0, "amount": 0, "date": today}
            if stats["count"] >= MAX_DAILY_TRANSFER_COUNT:
                return False, f"今日转账次数已达上限 ({MAX_DAILY_TRANSFER_COUNT} 笔)，请明日再试"
            if stats["amount"] + atomic_amount > MAX_DAILY_TRANSFER_AMOUNT:
                remaining = format_amount(MAX_DAILY_TRANSFER_AMOUNT - stats["amount"])
                return False, f"今日转账额度不足，剩余额度 {remaining} XODE"

            tx_hash = hashlib.sha256(
                json.dumps({
                    "from": from_addr,
                    "to": to_addr,
                    "amount": atomic_amount,
                    "nonce": tx_nonce
                }, sort_keys=True).encode()
            ).hexdigest()

            if tx_hash in self.pending_transactions:
                return False, "交易已在内存池中"

            tx = {
                "type": "transfer",
                "from": from_addr,
                "to": to_addr,
                "amount": from_atomic(atomic_amount),
                "fee": format_amount(atomic_fee),
                "amount_atomic": atomic_amount,
                "fee_atomic": atomic_fee,
                "timestamp": time.time(),
                "tx_timestamp": tx_timestamp,
                "nonce": tx_nonce,
                "status": "pending",
                "tx_hash": tx_hash,
                "public_key": public_key,
                "signature": signature
            }

            self._clean_expired_txs()

            if len(self.pending_transactions) >= MAX_MEMPOOL_SIZE:
                oldest_hash = min(self.pending_transactions, key=lambda k: self.pending_transactions[k].get('timestamp', float('inf')))
                del self.pending_transactions[oldest_hash]
                print(f'[Mempool] 内存池已满，移除最旧交易 {oldest_hash}', flush=True)

            self.pending_transactions[tx_hash] = tx

            stats["count"] += 1
            stats["amount"] += atomic_amount
            self.daily_transfer_stats[from_addr] = stats

            for addr in [from_addr, to_addr]:
                if addr not in self.transaction_history:
                    self.transaction_history[addr] = []
                self.transaction_history[addr].append(tx.copy())
                MAX_HISTORY = 200
                if len(self.transaction_history[addr]) > MAX_HISTORY * 2:
                    confirmed = [t for t in self.transaction_history[addr] if t.get("status") == "confirmed"]
                    pending = [t for t in self.transaction_history[addr] if t.get("status") != "confirmed"]
                    confirmed = confirmed[-MAX_HISTORY:]
                    self.transaction_history[addr] = confirmed + pending

            self.save_data()
            return True, tx

    def _execute_transactions_in_block(self, transactions):
        executed = []
        failed = []
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')

        for tx in transactions:
            from_addr = tx.get("from")
            to_addr = tx.get("to")
            amount_atomic = tx.get("amount_atomic", 0)
            fee_atomic = tx.get("fee_atomic", to_atomic(self.TRANSFER_FEE))
            tx_nonce = tx.get("nonce")
            total_needed = amount_atomic + fee_atomic

            stats = self.daily_transfer_stats.get(from_addr, {"count": 0, "amount": 0, "date": today})
            if stats.get("date") != today:
                stats = {"count": 0, "amount": 0, "date": today}
            if stats["count"] >= MAX_DAILY_TRANSFER_COUNT:
                print(f"[Mempool] 交易 {tx.get('tx_hash')} 日转账次数超限，跳过", flush=True)
                tx["_fail_reason"] = "daily_limit"
                failed.append(tx)
                continue
            if stats["amount"] + amount_atomic > MAX_DAILY_TRANSFER_AMOUNT:
                print(f"[Mempool] 交易 {tx.get('tx_hash')} 日转账额度超限，跳过", flush=True)
                tx["_fail_reason"] = "daily_limit"
                failed.append(tx)
                continue

            current_balance = self.balances.get(from_addr, 0)
            last_nonce = self.address_nonces.get(from_addr, -1)

            if tx_nonce <= last_nonce:
                print(f"[Mempool] 交易 {tx.get('tx_hash')} nonce 已过期，跳过", flush=True)
                tx["_fail_reason"] = "nonce_expired"
                failed.append(tx)
                continue

            if current_balance < total_needed:
                print(f"[Mempool] 交易 {tx.get('tx_hash')} 余额不足，跳过", flush=True)
                tx["_fail_reason"] = "insufficient_balance"
                failed.append(tx)
                continue

            current_balance = self.balances.get(from_addr, 0)
            last_nonce = self.address_nonces.get(from_addr, -1)

            if tx_nonce <= last_nonce:
                print(f"[Mempool] 交易 {tx.get('tx_hash')} nonce 已过期，跳过", flush=True)
                failed.append(tx)
                continue

            if current_balance < total_needed:
                print(f"[Mempool] 交易 {tx.get('tx_hash')} 余额不足，跳过", flush=True)
                failed.append(tx)
                continue

            self.balances[from_addr] = current_balance - total_needed

            if to_addr == BURN_ADDRESS:
                self.balances[BURN_ADDRESS] = self.balances.get(BURN_ADDRESS, 0) + total_needed
            else:
                self.balances[to_addr] = self.balances.get(to_addr, 0) + amount_atomic
                self.balances[BURN_ADDRESS] = self.balances.get(BURN_ADDRESS, 0) + fee_atomic

                current_height = len(self.chain)
                maturity_block = current_height + TX_CONFIRMATIONS

                if to_addr not in self.pending_transfers:
                    self.pending_transfers[to_addr] = []
                self.pending_transfers[to_addr].append({
                    "block_index": current_height,
                    "amount": amount_atomic,
                    "maturity_block": maturity_block,
                    "tx_hash": tx.get("tx_hash", ""),
                    "from": from_addr
                })

            stats["count"] += 1
            stats["amount"] += amount_atomic
            self.daily_transfer_stats[from_addr] = stats

            self.address_nonces[from_addr] = tx_nonce
            tx["status"] = "confirmed"
            executed.append(tx)
            print(f"[Mempool] 执行交易: {from_addr} -> {to_addr} {format_amount(amount_atomic)} XODE (手续费 {format_amount(fee_atomic)})", flush=True)

        return executed, failed

    def _remove_confirmed_from_mempool(self, confirmed_txs):
        confirmed_hashes = {tx.get("tx_hash") for tx in confirmed_txs}
        before = len(self.pending_transactions)
        for tx_hash in confirmed_hashes:
            if tx_hash in self.pending_transactions:
                del self.pending_transactions[tx_hash]
        after = len(self.pending_transactions)
        removed = before - after
        if removed > 0:
            print(f"[Mempool] 已移除 {removed} 笔已确认交易，池中剩余 {after} 笔", flush=True)

    def _clean_expired_txs(self):
        current_time = time.time()
        expired_hashes = []
        for tx_hash, tx in list(self.pending_transactions.items()):
            tx_time = tx.get('timestamp', 0)
            if current_time - tx_time > TX_MAX_LIFETIME:
                expired_hashes.append(tx_hash)
        for tx_hash in expired_hashes:
            del self.pending_transactions[tx_hash]
            if tx_hash in self.broadcasted_tx_hashes:
                self.broadcasted_tx_hashes.discard(tx_hash)
        if expired_hashes:
            print(f'[Mempool] 清理 {len(expired_hashes)} 笔过期交易（超过 {TX_MAX_LIFETIME // 3600} 小时未打包）', flush=True)
        return len(expired_hashes)

    def transfer(self, from_addr, to_addr, amount, signature=None, public_key=None,
                 tx_timestamp=None, tx_nonce=None, is_forwarded=False):
        return self.add_to_mempool(from_addr, to_addr, amount, signature, public_key,
                                   tx_timestamp, tx_nonce, is_forwarded)

    def _select_txs_for_block(self, all_txs):
        if not all_txs:
            return []
        sorted_txs = sorted(all_txs, key=lambda tx: (tx.get('from', ''), tx.get('nonce', 0)))
        selected = []
        total_size = 0
        for tx in sorted_txs:
            if len(selected) >= MAX_TX_PER_BLOCK:
                print(f'[出块] 达到最大交易数量限制 {MAX_TX_PER_BLOCK}，剩余 {len(sorted_txs) - len(selected)} 笔交易留在内存池', flush=True)
                break
            tx_size = len(json.dumps(tx, sort_keys=True, ensure_ascii=False).encode('utf-8'))
            if total_size + tx_size > MAX_BLOCK_SIZE:
                print(f'[出块] 达到最大区块大小限制 {MAX_BLOCK_SIZE} 字节，剩余 {len(sorted_txs) - len(selected)} 笔交易留在内存池', flush=True)
                break
            selected.append(tx)
            total_size += tx_size
        if len(selected) < len(sorted_txs):
            print(f'[出块] 本次打包 {len(selected)} 笔交易，{len(sorted_txs) - len(selected)} 笔留待下一块', flush=True)
        else:
            print(f'[出块] 内存池共 {len(selected)} 笔交易，全部打包', flush=True)
        return selected

    def _calc_block_size(self, transactions, reward_tx):
        block_dict = {
            "index": len(self.chain),
            "timestamp": time.time(),
            "previous_hash": self.chain[-1].hash if self.chain else "0" * 64,
            "reward_tx": reward_tx,
            "transactions": transactions
        }
        return len(json.dumps(block_dict, sort_keys=True, ensure_ascii=False).encode('utf-8'))

    def get_difficulty(self):
        import math

        if time.time() - getattr(self, 'node_start_time', 0) < 120:
            return self.get_difficulty_objective()

        if len(self.chain) <= 1:
            return float(self.INITIAL_DIFFICULTY)

        N = 10
        recent = self.chain[-N:]

        if len(recent) < 2:
            return float(self.chain[-1].difficulty)

        total_time = recent[-1].timestamp - recent[0].timestamp
        avg_interval = total_time / max(1, len(recent) - 1)
        avg_interval = max(self.BLOCK_TIME / 4, min(avg_interval, self.BLOCK_TIME * 10))
        time_factor = math.log2(self.BLOCK_TIME / avg_interval)

        producer_counts = {}
        for block in recent:
            reward_tx = getattr(block, 'reward_tx', {}) or {}
            node = reward_tx.get("producer_node", "UNKNOWN")
            producer_counts[node] = producer_counts.get(node, 0) + 1

        total_blocks = len(recent)
        producer_weights = {
            node: count / total_blocks
            for node, count in producer_counts.items()
        }

        online_producers = set()
        if self.is_producer and self.server_address:
            online_producers.add(self.server_address)

        with self.lock:
            current_time = time.time()
            for addr, info in self.all_online_users.items():
                if info.get("is_producer") and addr != self.server_address:
                    if current_time - info.get("last_seen", 0) <= self.ONLINE_PROOF_VALIDITY:
                        online_producers.add(addr)

        retained_ratio = sum(
            producer_weights.get(addr, 0)
            for addr in online_producers
        )

        dominant_node = max(producer_weights, key=producer_weights.get, default=None)
        dominant_weight = producer_weights.get(dominant_node, 0) if dominant_node else 0
        dominant_offline = dominant_node and dominant_node not in online_producers

        if dominant_offline and dominant_weight > 0.5:
            print(f"[HRPAD] 主导生产者 {dominant_node} 掉线，历史权重 {dominant_weight:.1%}", flush=True)

        if len(producer_counts) == 0:
            retained_ratio = 1.0
        elif retained_ratio < 0.001:
            retained_ratio = 0.01

        hashrate_factor = math.log2(max(0.001, retained_ratio))
        if dominant_offline and dominant_weight > 0.5:
            hashrate_factor += math.log2(max(0.01, 1 - dominant_weight))

        old_diff = float(self.chain[-1].difficulty)

        is_emergency = dominant_offline and dominant_weight > 0.5 and retained_ratio < 0.2

        if is_emergency:
            new_diff = float(self.INITIAL_DIFFICULTY)
            print(f"[HRPAD] 紧急重置难度 {old_diff:.2f} -> {new_diff:.2f}", flush=True)
            return float(new_diff)

        raw_new_diff = old_diff + time_factor + hashrate_factor
        max_change = 0.25
        new_diff = max(old_diff - max_change, min(old_diff + max_change, raw_new_diff))
        new_diff = max(1.0, min(250.0, new_diff))

        print(f"[HRPAD] 旧难度:{old_diff:.4f} 时间:{time_factor:+.4f} 算力:{hashrate_factor:+.4f} "
              f"平均间隔:{avg_interval:.0f}s 保留:{retained_ratio:.1%} 在线生产者:{len(online_producers)} "
              f"-> 新难度:{new_diff:.4f}", flush=True)

        return float(new_diff)

    def get_difficulty_objective(self, block_index=None):
        import math

        if len(self.chain) <= 1:
            return float(self.INITIAL_DIFFICULTY)

        N = 10
        if block_index is None:
            recent = self.chain[-N:]
        else:
            start = max(0, block_index - N)
            recent = self.chain[start:block_index]

        if len(recent) < 2:
            return float(self.chain[-1].difficulty) if self.chain else float(self.INITIAL_DIFFICULTY)

        total_time = recent[-1].timestamp - recent[0].timestamp
        avg_interval = total_time / max(1, len(recent) - 1)
        avg_interval = max(self.BLOCK_TIME / 4, min(avg_interval, self.BLOCK_TIME * 10))
        time_factor = math.log2(self.BLOCK_TIME / avg_interval)

        if block_index is not None and block_index < len(self.chain):
            old_diff = float(self.chain[block_index - 1].difficulty) if block_index > 0 else float(self.INITIAL_DIFFICULTY)
        else:
            old_diff = float(self.chain[-1].difficulty) if self.chain else float(self.INITIAL_DIFFICULTY)

        raw_new_diff = old_diff + time_factor
        max_change = 0.25
        new_diff = max(old_diff - max_change, min(old_diff + max_change, raw_new_diff))
        new_diff = max(1.0, min(250.0, new_diff))
        return float(new_diff)


    def _get_expected_difficulty(self, block_index):
        if block_index <= 1:
            return float(self.INITIAL_DIFFICULTY)
        return self.get_difficulty_objective(block_index)

    def _validate_block_pow(self, block):
        hash_int = int(block.hash, 16)
        target = difficulty_to_target(block.difficulty)
        if hash_int >= target:
            return False, f"POW 验证失败：哈希值不满足难度要求 (difficulty={block.difficulty:.4f}, target={hex(target)[:30]}...)"
        calculated = block.calculate_hash()
        if block.hash != calculated:
            import json as _json
            debug_data = {
                "index": block.index,
                "timestamp": block.timestamp,
                "previous_hash": block.previous_hash,
                "reward_tx": block.reward_tx,
                "transactions": block.transactions,
                "nonce": block.nonce,
                "difficulty": block.difficulty
            }
            debug_str = _json.dumps(debug_data, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
            print(f"[POW调试] 预期hash: {calculated}", flush=True)
            print(f"[POW调试] 实际hash: {block.hash}", flush=True)
            print(f"[POW调试] 序列化前200字符: {debug_str[:200]}", flush=True)
            return False, "POW 验证失败：哈希计算不匹配"

        if self.syncing:
            return True, None

        objective_difficulty = self.get_difficulty_objective(block.index)
        if block.difficulty < objective_difficulty - 0.01:
            return False, f"难度过低：区块难度 {block.difficulty:.4f}，最低允许 {objective_difficulty:.4f}"

        expected_difficulty = self.get_difficulty()
        diff = abs(block.difficulty - expected_difficulty)
        if diff > 0.5:
            print(f"[P2P] 区块 #{block.index} 难度偏差 {diff:.4f} (区块:{block.difficulty:.4f} 预期:{expected_difficulty:.4f})，但POW有效且满足客观难度，接受", flush=True)

        return True, None


    def _get_locator_hashes(self):
        with self.chain_lock:
            if not self.chain:
                return []
            locator = []
            step = 1
            index = len(self.chain) - 1
            while index >= 0:
                locator.append(self.chain[index].hash)
                if len(locator) >= 10:
                    step *= 2
                index -= step
            if self.chain and self.chain[0].hash not in locator:
                locator.append(self.chain[0].hash)
            return locator

    def _request_headers_from_peer(self, sock, start_hash=None):
        locator = self._get_locator_hashes()
        if start_hash:
            locator.insert(0, start_hash)
        msg = {
            "type": "getheaders",
            "address": self.server_address,
            "locator": locator,
            "hashstop": "0" * 64
        }
        try:
            sock.sendall(encode_message(msg))
            print(f"[P2P同步] 向节点发送 getheaders，locator 包含 {len(locator)} 个哈希", flush=True)
        except Exception as e:
            print(f"[P2P同步] 发送 getheaders 失败: {e}", flush=True)

    def _process_headers(self, headers, peer_sock):
        if not headers:
            return

        with self.sync_lock:
            needed_blocks = []
            last_connected = None
            is_last_batch = len(headers) < MAX_HEADERS_RESULTS

            for header in headers:
                idx = header.get("index")
                h = header.get("hash")
                prev = header.get("previous_hash")

                if h in self.block_inventory:
                    last_connected = header
                    continue

                connects = False
                if not self.chain:
                    if idx == 0:
                        connects = True
                else:
                    if prev == self.chain[-1].hash:
                        connects = True
                    elif prev in self.block_inventory:
                        connects = True
                    elif prev in self.orphan_blocks:
                        connects = True

                if connects or last_connected is not None:
                    needed_blocks.append(h)
                    last_connected = header
                else:
                    print(f"[P2P同步] 区块头 #{idx} {h[:16]}... 无法连接，跳过", flush=True)

            if needed_blocks:
                existing = set(self.sync_block_queue)
                added = 0
                for h in needed_blocks:
                    if h not in existing and h not in self.block_inventory and h not in self.pending_block_requests:
                        self.sync_block_queue.append(h)
                        existing.add(h)
                        added += 1
                print(f"[P2P同步] 队列新增 {added} 个区块，队列总长 {len(self.sync_block_queue)}", flush=True)
                if is_last_batch:
                    self.headers_synced = True
                    print(f"[P2P同步] 所有 headers 已接收，队列共 {len(self.sync_block_queue)} 个区块待下载", flush=True)
                self._request_next_sync_batch(peer_sock)
            else:
                print(f"[P2P同步] 所有区块头已存在或无法连接", flush=True)
                if is_last_batch:
                    self.headers_synced = True
                    if not self.sync_block_queue and not self.pending_block_requests:
                        self.syncing = False
                    print(f"[P2P同步] Headers 同步完成，链高度 #{len(self.chain)-1}", flush=True)

    def _request_blocks_by_hashes(self, sock, hashes):
        if not hashes:
            return
        for i in range(0, len(hashes), MAX_BLOCKS_PER_GETDATA):
            batch = hashes[i:i + MAX_BLOCKS_PER_GETDATA]
            msg = {
                "type": "getdata",
                "address": self.server_address,
                "inventory": [{"type": "block", "hash": h} for h in batch]
            }
            try:
                sock.sendall(encode_message(msg))
                for h in batch:
                    self.pending_block_requests.add(h)
                print(f"[P2P同步] 请求 {len(batch)} 个区块 (getdata)", flush=True)
            except Exception as e:
                print(f"[P2P同步] 发送 getdata 失败: {e}", flush=True)

    def _request_next_sync_batch(self, sock):
        with self.sync_lock:
            slots = max(0, MAX_BLOCKS_PER_GETDATA - len(self.pending_block_requests))
            if slots <= 0:
                return
            to_request = []
            for h in list(self.sync_block_queue):
                if h in self.block_inventory:
                    self.sync_block_queue.remove(h)
                    continue
                if h not in self.pending_block_requests:
                    to_request.append(h)
                    if len(to_request) >= slots:
                        break
            if not to_request:
                return
            msg = {
                "type": "getdata",
                "address": self.server_address,
                "inventory": [{"type": "block", "hash": h} for h in to_request]
            }
            try:
                sock.sendall(encode_message(msg))
                for h in to_request:
                    self.pending_block_requests.add(h)
                print(f"[P2P同步] 流水线请求 {len(to_request)} 个区块 "
                      f"(pending:{len(self.pending_block_requests)} 队列剩余:{len(self.sync_block_queue)})", flush=True)
            except Exception as e:
                print(f"[P2P同步] 发送 getdata 失败: {e}", flush=True)

    def _get_chain_work(self, blocks):
        return sum(float(b.difficulty) for b in blocks)

    def _get_orphan_chain_work(self, tail_hash):
        work = 0.0
        current = tail_hash
        visited = {current}
        while True:
            block_data = self.orphan_blocks.get(current)
            if not block_data:
                break
            work += float(block_data.get("difficulty", self.INITIAL_DIFFICULTY))
            prev_hash = block_data.get("previous_hash")
            if any(b.hash == prev_hash for b in self.chain):
                break
            if prev_hash in self.orphan_blocks and prev_hash not in visited:
                current = prev_hash
                visited.add(current)
            else:
                break
        return work

    def _process_orphan_blocks(self):
        connected_any = True
        while connected_any:
            connected_any = False
            orphans_to_remove = []
            for h, block_data in list(self.orphan_blocks.items()):
                prev_hash = block_data.get("previous_hash")
                parent_in_chain = any(b.hash == prev_hash for b in self.chain)
                if parent_in_chain:
                    print(f"[P2P孤儿] 孤儿块 {h[:16]}... 找到父块，尝试连接", flush=True)
                    if self._try_connect_block(block_data):
                        orphans_to_remove.append(h)
                        connected_any = True
            for h in orphans_to_remove:
                if h in self.orphan_blocks:
                    del self.orphan_blocks[h]

        chain_built = True
        while chain_built:
            chain_built = False
            orphan_tails = [
                (h, bd) for h, bd in self.orphan_blocks.items()
                if not any(b.get("previous_hash") == h for b in self.orphan_blocks.values())
            ]

            for h, block_data in orphan_tails:
                prev_hash = block_data.get("previous_hash")
                parent_in_main = any(b.hash == prev_hash for b in self.chain)
                if not parent_in_main and prev_hash not in self.orphan_blocks:
                    continue

                chain_length = self._get_orphan_chain_length(h)
                fork_point = self._get_orphan_fork_point(h)
                if fork_point < 0:
                    continue

                main_branch_blocks = self.chain[fork_point + 1:]
                main_branch_work = self._get_chain_work(main_branch_blocks)
                orphan_work = self._get_orphan_chain_work(h)
                main_branch_length = len(main_branch_blocks)

                should_switch = False

                if orphan_work > main_branch_work:
                    print(f"[P2P分叉] 孤儿链 work={orphan_work:.2f}(长度{chain_length}) vs 主链分支 work={main_branch_work:.2f}(长度{main_branch_length})，工作量占优", flush=True)
                    should_switch = True
                elif abs(orphan_work - main_branch_work) < 0.0001:
                    if chain_length > main_branch_length:
                        print(f"[P2P分叉] 工作量相等，孤儿链更长({chain_length} > {main_branch_length})，切换", flush=True)
                        should_switch = True
                    elif chain_length == main_branch_length:
                        main_latest_ts = main_branch_blocks[-1].timestamp if main_branch_blocks else 0
                        orphan_latest_ts = block_data.get("timestamp", 0)
                        if orphan_latest_ts < main_latest_ts:
                            print(f"[P2P分叉] 工作量与长度均相等，孤儿链时间戳更早({orphan_latest_ts} < {main_latest_ts})，优先切换", flush=True)
                            should_switch = True
                        elif orphan_latest_ts == main_latest_ts:
                            main_latest_hash = main_branch_blocks[-1].hash if main_branch_blocks else "z"
                            orphan_latest_hash = h
                            if orphan_latest_hash < main_latest_hash:
                                print(f"[P2P分叉] 工作量/长度/时间戳均相等，孤儿链哈希更小，优先切换", flush=True)
                                should_switch = True

                if should_switch:
                    print(f"[P2P分叉] 孤儿链胜出，执行链切换", flush=True)
                    if self._switch_to_orphan_chain(h):
                        chain_built = True
                        break
                else:
                    removed = self._purge_orphan_branch(h)
                    if removed > 0:
                        print(f"[P2P孤儿] 清理劣势孤儿链 {h[:16]}...，共 {removed} 个区块", flush=True)

        if len(self.orphan_blocks) > MAX_ORPHAN_BLOCKS:
            sorted_orphans = sorted(self.orphan_blocks.items(),
                                    key=lambda x: x[1].get("timestamp", 0))
            to_remove = len(self.orphan_blocks) - MAX_ORPHAN_BLOCKS
            for h, _ in sorted_orphans[:to_remove]:
                del self.orphan_blocks[h]
            print(f"[P2P孤儿] 清理 {to_remove} 个旧孤儿块，剩余 {len(self.orphan_blocks)}", flush=True)

    def _get_orphan_chain_length(self, tail_hash):
        length = 1
        current = tail_hash
        visited = {current}
        while True:
            block_data = self.orphan_blocks.get(current)
            if not block_data:
                break
            prev_hash = block_data.get("previous_hash")
            if any(b.hash == prev_hash for b in self.chain):
                break
            if prev_hash in self.orphan_blocks and prev_hash not in visited:
                length += 1
                current = prev_hash
                visited.add(current)
            else:
                break
        return length

    def _get_orphan_fork_point(self, tail_hash):
        current = tail_hash
        visited = {current}
        while True:
            block_data = self.orphan_blocks.get(current)
            if not block_data:
                return -1
            prev_hash = block_data.get("previous_hash")
            for i, b in enumerate(self.chain):
                if b.hash == prev_hash:
                    return i
            if prev_hash in self.orphan_blocks and prev_hash not in visited:
                current = prev_hash
                visited.add(current)
            else:
                return -1

    def _purge_orphan_branch(self, tail_hash):
        current = tail_hash
        removed = 0
        while current and current in self.orphan_blocks:
            has_children = any(
                bd.get("previous_hash") == current
                for bd in self.orphan_blocks.values()
            )
            if has_children:
                break
            prev = self.orphan_blocks[current].get("previous_hash")
            del self.orphan_blocks[current]
            removed += 1
            current = prev
        return removed

    def _switch_to_orphan_chain(self, tail_hash):
        orphan_chain = []
        current = tail_hash
        visited = {current}
        fork_idx = -1
        while True:
            block_data = self.orphan_blocks.get(current)
            if not block_data:
                return False
            orphan_chain.append((current, block_data))
            prev_hash = block_data.get("previous_hash")
            found = False
            for i, b in enumerate(self.chain):
                if b.hash == prev_hash:
                    fork_idx = i
                    found = True
                    break
            if found:
                break
            if prev_hash in self.orphan_blocks and prev_hash not in visited:
                current = prev_hash
                visited.add(current)
            else:
                return False

        if fork_idx < 0:
            return False

        orphan_chain.reverse()

        print(f"[P2P分叉] 截断主链从 #{fork_idx+1} 开始，切换到孤儿链 ({len(orphan_chain)} 个区块)", flush=True)

        with self.chain_lock:
            removed_blocks = self.chain[fork_idx+1:]
            self.chain = self.chain[:fork_idx+1]
            for b in removed_blocks:
                self.orphan_blocks[b.hash] = b.to_dict()
            for b in removed_blocks:
                if b.hash in self.block_inventory:
                    self.block_inventory.discard(b.hash)
            for h, block_data in orphan_chain:
                new_block = Block(
                    index=block_data["index"],
                    timestamp=block_data["timestamp"],
                    previous_hash=block_data["previous_hash"],
                    reward_tx=block_data.get("reward_tx", {}),
                    transactions=block_data.get("transactions", []),
                    nonce=block_data.get("nonce", 0),
                    difficulty=block_data.get("difficulty", self.INITIAL_DIFFICULTY),
                    hash=block_data.get("hash")
                )
                self.chain.append(new_block)
                self.block_inventory.add(new_block.hash)
                if h in self.orphan_blocks:
                    del self.orphan_blocks[h]

        self._rebuild_state_from_chain()
        self.save_data()
        print(f"[P2P分叉] 链切换完成，新高度 #{len(self.chain)-1}", flush=True)
        return True

    def _rebuild_state_from_chain(self):
        print(f"[P2P重建] 开始从创世块重建状态...", flush=True)

        old_history = {k: v[:] for k, v in self.transaction_history.items()}
        old_ip_bindings = {k: v.copy() for k, v in self.ip_bindings.items()}
        old_first_seen = self.address_first_seen_block.copy()
        old_pending_tx = dict(self.pending_transactions)

        self.balances = {}
        self.pending_rewards = {}
        self.pending_transfers = {}
        self.total_issued = 0
        self.address_nonces = {}
        self.daily_transfer_stats = {}
        self.broadcasted_tx_hashes = set()

        chain_tx_hashes = set()
        for block in self.chain:
            for tx in block.transactions:
                tx_hash = tx.get("tx_hash")
                if tx_hash:
                    chain_tx_hashes.add(tx_hash)

        cleaned_history = {}
        for addr, txs in old_history.items():
            cleaned = []
            for tx in txs:
                tx_hash = tx.get("tx_hash")
                if tx.get("status") == "confirmed" and tx_hash and tx_hash not in chain_tx_hashes:
                    tx_copy = tx.copy()
                    tx_copy["status"] = "orphaned"
                    tx_copy["confirmations"] = 0
                    tx_copy["block_index"] = None
                    cleaned.append(tx_copy)
                else:
                    cleaned.append(tx)
            cleaned_history[addr] = cleaned
        old_history = cleaned_history

        for block in self.chain:
            idx = block.index
            reward_tx = block.reward_tx

            for r in reward_tx.get("recipients", []):
                addr = r.get("address")
                amt = r.get("amount_atomic")
                if amt is None:
                    amt = to_atomic(r.get("amount", 0))
                if addr and amt > 0:
                    self.balances[addr] = self.balances.get(addr, 0) + amt
                    maturity = r.get("maturity_block", idx + REWARD_CONFIRMATIONS)
                    if addr not in self.pending_rewards:
                        self.pending_rewards[addr] = []
                    self.pending_rewards[addr].append({
                        "block_index": idx,
                        "amount": amt,
                        "maturity_block": maturity
                    })

            self.total_issued += to_atomic(reward_tx.get("total", 0))

            today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            for tx in block.transactions:
                if tx.get("type") == "transfer":
                    from_addr = tx.get("from")
                    to_addr = tx.get("to")
                    amount = tx.get("amount_atomic")
                    if amount is None:
                        amount = to_atomic(tx.get("amount", 0))
                    fee = tx.get("fee_atomic")
                    if fee is None:
                        if tx.get("fee") is not None:
                            fee = to_atomic(tx.get("fee"))
                        else:
                            fee = to_atomic(self.TRANSFER_FEE)

                    tx_nonce = tx.get("nonce")
                    if tx_nonce is not None and from_addr:
                        self.address_nonces[from_addr] = tx_nonce

                    if from_addr and from_addr != "GENESIS":
                        self.balances[from_addr] = self.balances.get(from_addr, 0) - amount - fee
                    if to_addr == BURN_ADDRESS:
                        self.balances[BURN_ADDRESS] = self.balances.get(BURN_ADDRESS, 0) + amount + fee
                    elif to_addr:
                        self.balances[to_addr] = self.balances.get(to_addr, 0) + amount
                        if fee > 0:
                            self.balances[BURN_ADDRESS] = self.balances.get(BURN_ADDRESS, 0) + fee
                        maturity = idx + TX_CONFIRMATIONS
                        if to_addr not in self.pending_transfers:
                            self.pending_transfers[to_addr] = []
                        self.pending_transfers[to_addr].append({
                            "block_index": idx,
                            "amount": amount,
                            "maturity_block": maturity,
                            "tx_hash": tx.get("tx_hash", ""),
                            "from": from_addr
                        })
                    elif fee > 0:
                        self.balances[BURN_ADDRESS] = self.balances.get(BURN_ADDRESS, 0) + fee

                    if from_addr and from_addr != "GENESIS":
                        stats = self.daily_transfer_stats.get(from_addr, {"count": 0, "amount": 0, "date": today})
                        if stats.get("date") != today:
                            stats = {"count": 0, "amount": 0, "date": today}
                        stats["count"] += 1
                        stats["amount"] += amount
                        self.daily_transfer_stats[from_addr] = stats

        self.transaction_history = old_history
        self.ip_bindings = old_ip_bindings
        self.address_first_seen_block = old_first_seen
        self.pending_transactions = old_pending_tx
        self._recalc_total_issued_from_chain()
        print(f"[P2P重建] 状态重建完成，高度 #{len(self.chain)-1}，已发行 {format_amount(self.total_issued)} XODE", flush=True)

    def _validate_synced_transactions(self, transactions, block_index):
        if not transactions:
            return True, None

        temp_balances = {}
        temp_nonces = {}
        temp_daily_stats = {}
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')

        with self.lock:
            base_balances = self.balances.copy()
            base_nonces = self.address_nonces.copy()
            base_daily_stats = {k: v.copy() for k, v in self.daily_transfer_stats.items()}

        for tx in transactions:
            tx_type = tx.get("type")
            if tx_type != "transfer":
                continue

            from_addr = tx.get("from")
            to_addr = tx.get("to")
            amount_atomic = tx.get("amount_atomic")
            if amount_atomic is None:
                amount_atomic = to_atomic(tx.get("amount", 0))
            fee_atomic = tx.get("fee_atomic")
            if fee_atomic is None:
                fee_atomic = to_atomic(self.TRANSFER_FEE)
            tx_nonce = tx.get("nonce")
            public_key = tx.get("public_key")
            signature = tx.get("signature")
            tx_timestamp = tx.get("tx_timestamp") or tx.get("timestamp")

            if not public_key:
                return False, f"交易缺少公钥"
            if not signature:
                return False, f"交易缺少签名"
            if not verify_public_key_address(public_key, from_addr):
                return False, f"公钥与地址不匹配: {from_addr}"
            if not self.is_valid_xode_address(to_addr):
                return False, f"目标地址无效: {to_addr}"
            if from_addr == to_addr:
                return False, f"不能转账给自己: {from_addr}"
            if amount_atomic <= 0:
                return False, f"转账金额必须大于0"
            if amount_atomic > MAX_TRANSFER_AMOUNT:
                max_display = format_amount(MAX_TRANSFER_AMOUNT)
                return False, f"单笔转账金额超过限制，最大允许 {max_display} XODE"

            message = build_sign_message(from_addr, to_addr, tx.get("amount", 0), tx_nonce, tx_timestamp)
            if not verify_signature(public_key, message, signature, timestamp=tx_timestamp):
                return False, f"交易签名验证失败: {from_addr} -> {to_addr}"

            last_nonce = temp_nonces.get(from_addr, base_nonces.get(from_addr, -1))
            if tx_nonce <= last_nonce:
                return False, f"交易 nonce 无效: {tx_nonce} (已使用: {last_nonce})，请勿重放交易"

            current_bal = temp_balances.get(from_addr, base_balances.get(from_addr, 0))
            total_needed = amount_atomic + fee_atomic
            if current_bal < total_needed:
                return False, f"余额不足: {from_addr} 需要 {format_amount(total_needed)} 仅有 {format_amount(current_bal)}"

            stats = temp_daily_stats.get(from_addr, base_daily_stats.get(from_addr, {"count": 0, "amount": 0, "date": today})).copy()
            if stats.get("date") != today:
                stats = {"count": 0, "amount": 0, "date": today}
            if stats["count"] >= MAX_DAILY_TRANSFER_COUNT:
                return False, f"日转账次数超限: {from_addr}"
            if stats["amount"] + amount_atomic > MAX_DAILY_TRANSFER_AMOUNT:
                return False, f"日转账额度超限: {from_addr}"

            temp_balances[from_addr] = current_bal - total_needed
            if to_addr == BURN_ADDRESS:
                temp_balances[BURN_ADDRESS] = temp_balances.get(BURN_ADDRESS, base_balances.get(BURN_ADDRESS, 0)) + total_needed
            else:
                temp_balances[to_addr] = temp_balances.get(to_addr, base_balances.get(to_addr, 0)) + amount_atomic
                temp_balances[BURN_ADDRESS] = temp_balances.get(BURN_ADDRESS, base_balances.get(BURN_ADDRESS, 0)) + fee_atomic

            temp_nonces[from_addr] = tx_nonce
            stats["count"] += 1
            stats["amount"] += amount_atomic
            temp_daily_stats[from_addr] = stats

        return True, None

    def _validate_reward_tx(self, reward_tx, block_index):
        total_atomic = reward_tx.get("total_atomic")
        if total_atomic is None:
            total_atomic = to_atomic(reward_tx.get("total", 0))

        if total_atomic < 0:
            return False, "区块奖励不能为负数"

        if block_index == 0:
            return True, None

        max_reward_atomic = to_atomic(self.BLOCK_REWARD)
        if total_atomic > max_reward_atomic:
            return False, f"区块奖励超过最大允许值 {self.BLOCK_REWARD} XODE"

        with self.lock:
            remaining = to_atomic(self.TOTAL_SUPPLY) - self.total_issued
        if total_atomic > remaining:
            return False, f"区块奖励超过剩余供应量 {from_atomic(remaining)} XODE"

        if remaining <= 0 and total_atomic > 0:
            return False, "总量已达上限，奖励应为 0"

        recipients = reward_tx.get("recipients", [])
        if not recipients:
            return False, "奖励分配列表为空"

        sum_atomic = 0
        producer_reward_atomic = 0
        burn_amount = 0
        online_rewards = []

        producer_node = reward_tx.get("producer_node", "")
        producer_eligible = reward_tx.get("producer_eligible", False)

        for r in recipients:
            amt = r.get("amount_atomic")
            if amt is None:
                amt = to_atomic(r.get("amount", 0))
            sum_atomic += amt

            addr = r.get("address", "")
            if addr == BURN_ADDRESS:
                burn_amount += amt
            elif addr == producer_node and r.get("is_producer", False):
                producer_reward_atomic = amt
            elif addr != BURN_ADDRESS:
                online_rewards.append(amt)

        if sum_atomic != total_atomic:
            return False, f"奖励分配总额 {sum_atomic} 不等于区块奖励 {total_atomic}"

        expected_producer = int(total_atomic * PRODUCER_REWARD_SHARE)
        if producer_eligible:
            if abs(producer_reward_atomic - expected_producer) > 1:
                return False, f"出块节点奖励 {producer_reward_atomic} 与预期 {expected_producer} 不符"
        else:
            if producer_reward_atomic != 0:
                return False, "出块节点未满足资格但获得了奖励"

        if online_rewards:
            first = online_rewards[0]
            if not all(abs(r - first) <= 1 for r in online_rewards):
                return False, "在线用户奖励分配不均"

            expected_burn = total_atomic - producer_reward_atomic - sum(online_rewards)
            if abs(burn_amount - expected_burn) > 1:
                return False, f"销毁金额 {burn_amount} 与预期 {expected_burn} 不符"
        else:
            expected_burn = total_atomic - producer_reward_atomic
            if abs(burn_amount - expected_burn) > 1:
                return False, f"无在线用户时销毁金额 {burn_amount} 与预期 {expected_burn} 不符"

        return True, None

    def _try_connect_block(self, block_data):
        idx = block_data.get("index")
        h = block_data.get("hash")
        prev = block_data.get("previous_hash")
        local_height = len(self.chain) - 1

        if self.syncing and not self.headers_synced:
            if idx > local_height + 50:
                print(f"[P2P同步] 丢弃未来广播区块 #{idx}，本地仅 #{local_height}", flush=True)
                return False

        if h in self.block_inventory:
            return True

        with self.chain_lock:
            if self.chain and prev != self.chain[-1].hash:
                if idx < len(self.chain):
                    existing = self.chain[idx]
                    if existing.hash == h:
                        return True
                    else:
                        print(f"[P2P分叉] 检测到分叉: #{idx} 现有 {existing.hash[:16]}... 收到 {h[:16]}...，暂存孤儿池等待链切换", flush=True)
                        if h not in self.orphan_blocks:
                            self.orphan_blocks[h] = block_data
                        return False
                else:
                    if h not in self.orphan_blocks:
                        self.orphan_blocks[h] = block_data
                        print(f"[P2P孤儿] 区块 #{idx} {h[:16]}... 父块不在链尾，加入孤儿池", flush=True)
                    return False

            valid, err = self._validate_block_timestamp(block_data.get("timestamp", 0), block_index=idx)
            if not valid:
                print(f"[P2P] 区块 #{idx} 时间戳验证失败: {err}", flush=True)
                return False

            new_block = Block(
                index=block_data["index"],
                timestamp=block_data["timestamp"],
                previous_hash=block_data["previous_hash"],
                reward_tx=block_data.get("reward_tx", {}),
                transactions=block_data.get("transactions", []),
                nonce=block_data.get("nonce", 0),
                difficulty=block_data.get("difficulty", self.INITIAL_DIFFICULTY),
                hash=block_data.get("hash")
            )

            pow_valid, pow_err = self._validate_block_pow(new_block)
            if not pow_valid:
                print(f"[P2P] 区块 #{idx} {pow_err}", flush=True)
                return False

            tx_count = len(block_data.get('transactions', []))
            if tx_count > MAX_TX_PER_BLOCK:
                print(f'[P2P] 区块 #{idx} 交易数量 {tx_count} 超过限制 {MAX_TX_PER_BLOCK}，拒绝', flush=True)
                return False

            block_size = len(json.dumps(block_data, sort_keys=True, ensure_ascii=False).encode('utf-8'))
            if block_size > MAX_BLOCK_SIZE:
                print(f'[P2P] 区块 #{idx} 大小 {block_size} 字节超过限制 {MAX_BLOCK_SIZE}，拒绝', flush=True)
                return False

            txs = block_data.get('transactions', [])
            if txs:
                tx_valid, tx_err = self._validate_synced_transactions(txs, idx)
                if not tx_valid:
                    print(f"[P2P] 区块 #{idx} 交易验证失败: {tx_err}，拒绝", flush=True)
                    return False

            reward_tx = block_data.get("reward_tx", {})
            reward_valid, reward_err = self._validate_reward_tx(reward_tx, idx)
            if not reward_valid:
                print(f"[P2P] 区块 #{idx} 奖励验证失败: {reward_err}，拒绝", flush=True)
                return False

            return self._connect_block_to_chain(new_block, block_data)

    def _connect_block_to_chain(self, new_block, block_data):
        idx = new_block.index

        with self.chain_lock:
            if self.chain and idx != len(self.chain):
                if idx < len(self.chain):
                    return False
                else:
                    self.orphan_blocks[new_block.hash] = block_data
                    print(f"[P2P孤儿] 区块 #{idx} 是未来区块，加入孤儿池等待", flush=True)
                    return False

            self.chain.append(new_block)
            self.block_inventory.add(new_block.hash)

        for tx in block_data.get('transactions', []):
            tx['block_index'] = idx
            tx['confirmations'] = 0
            tx['status'] = 'confirmed'

        with self.lock:
            today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            reward_tx = block_data.get("reward_tx", {})

            for r in reward_tx.get("recipients", []):
                addr = r.get("address")
                amt_atomic = r.get("amount_atomic")
                if amt_atomic is not None:
                    amt = amt_atomic
                else:
                    amt = to_atomic(r.get("amount", 0))
                if addr and amt > 0:
                    self.balances[addr] = self.balances.get(addr, 0) + amt
                    maturity = r.get("maturity_block", idx + REWARD_CONFIRMATIONS)
                    if addr not in self.pending_rewards:
                        self.pending_rewards[addr] = []
                    self.pending_rewards[addr].append({
                        "block_index": idx,
                        "amount": amt,
                        "maturity_block": maturity
                    })

            block_reward = reward_tx.get("total", 0)
            self.total_issued += to_atomic(block_reward)

            confirmed_hashes = set()
            for tx in block_data.get("transactions", []):
                tx_type = tx.get("type")
                if tx_type == "transfer":
                    from_addr = tx.get("from")
                    to_addr = tx.get("to")
                    amount_atomic = tx.get("amount_atomic")
                    fee_atomic = tx.get("fee_atomic")
                    amount = amount_atomic if amount_atomic is not None else to_atomic(tx.get("amount", 0))
                    if fee_atomic is not None:
                        fee = fee_atomic
                    elif tx.get("fee") is not None:
                        fee = to_atomic(tx.get("fee"))
                    else:
                        fee = to_atomic(self.TRANSFER_FEE)

                    tx_nonce = tx.get("nonce")
                    if tx_nonce is not None and from_addr:
                        current_nonce = self.address_nonces.get(from_addr, -1)
                        if tx_nonce <= current_nonce:
                            print(f"[P2P警告] 区块 #{idx} 包含重复 nonce 交易，跳过执行", flush=True)
                            continue
                        else:
                            self.address_nonces[from_addr] = tx_nonce

                    if from_addr and from_addr != "GENESIS":
                        self.balances[from_addr] = self.balances.get(from_addr, 0) - amount - fee
                    if to_addr == BURN_ADDRESS:
                        self.balances[BURN_ADDRESS] = self.balances.get(BURN_ADDRESS, 0) + amount + fee
                    elif to_addr:
                        self.balances[to_addr] = self.balances.get(to_addr, 0) + amount
                        if fee > 0:
                            self.balances[BURN_ADDRESS] = self.balances.get(BURN_ADDRESS, 0) + fee
                        maturity = idx + TX_CONFIRMATIONS
                        if to_addr not in self.pending_transfers:
                            self.pending_transfers[to_addr] = []
                        self.pending_transfers[to_addr].append({
                            "block_index": idx,
                            "amount": amount,
                            "maturity_block": maturity,
                            "tx_hash": tx.get("tx_hash", ""),
                            "from": from_addr
                        })
                    elif fee > 0:
                        self.balances[BURN_ADDRESS] = self.balances.get(BURN_ADDRESS, 0) + fee

                    if from_addr and from_addr != "GENESIS":
                        stats = self.daily_transfer_stats.get(from_addr, {"count": 0, "amount": 0, "date": today})
                        if stats.get("date") != today:
                            stats = {"count": 0, "amount": 0, "date": today}
                        stats["count"] += 1
                        stats["amount"] += amount
                        self.daily_transfer_stats[from_addr] = stats

                    tx_hash = tx.get("tx_hash")
                    if tx_hash:
                        confirmed_hashes.add(tx_hash)
                        if tx_hash in self.broadcasted_tx_hashes:
                            self.broadcasted_tx_hashes.discard(tx_hash)

            before = len(self.pending_transactions)
            for tx_hash in list(confirmed_hashes):
                if tx_hash in self.pending_transactions:
                    del self.pending_transactions[tx_hash]
            removed = before - len(self.pending_transactions)
            if removed > 0:
                print(f"[Mempool] 同步节点移除 {removed} 笔已确认交易，池中剩余 {len(self.pending_transactions)} 笔", flush=True)

            self._recalc_total_issued_from_chain()

        self.save_data()
        self.scan_address_history()
        self._process_orphan_blocks()
        print(f"[P2P] 已连接区块 #{idx}，本地高度: #{len(self.chain)-1}，已发行: {format_amount(self.total_issued)} XODE", flush=True)
        self.broadcast_block_to_clients(new_block)
        return True

    def produce_block(self):
        online_users = self._get_all_online_users_for_reward()

        unique_addresses = set()
        unique_online_users = []
        for user in online_users:
            addr = user["address"]
            if addr not in unique_addresses:
                unique_addresses.add(addr)
                unique_online_users.append(user)

        if self.server_address not in unique_addresses and self.server_address != BURN_ADDRESS:
            unique_online_users.append({
                "address": self.server_address,
                "socket": None,
                "first_seen_block": self.address_first_seen_block.get(self.server_address),
                "source": "self"
            })
            unique_addresses.add(self.server_address)

        now = time.time()
        current_mtp = self.get_median_time_past()
        block_timestamp = max(int(now), current_mtp + 1)
        new_block_index = len(self.chain)

        print(f"[POW] 本节点 ({self.server_address}) 开始竞争出块权，目标区块 #{new_block_index}", flush=True)

        eligible_users = []
        ineligible_users = []
        current_height_check = len(self.chain) - 1
        for user in unique_online_users:
            addr = user["address"]
            if addr == BURN_ADDRESS:
                continue
            first_seen = self.address_first_seen_block.get(addr)
            if first_seen is None:
                self.address_first_seen_block[addr] = current_height_check
                first_seen = current_height_check
                print(f"[延迟分奖] 新用户 {addr} 首次记录于区块 #{current_height_check}", flush=True)
            blocks_waited = current_height_check - first_seen
            if blocks_waited >= BLOCKS_BEFORE_REWARD:
                eligible_users.append(user)
            else:
                ineligible_users.append(user)
                remaining = BLOCKS_BEFORE_REWARD - blocks_waited
                print(f"[延迟分奖] {addr} 已等待 {blocks_waited} 区块，还需 {remaining} 个区块才参与分奖", flush=True)

        online_count = len(eligible_users)

        remote_sources = {}
        for u in unique_online_users:
            src = u.get("source", "unknown")
            if src not in ("local", "self"):
                remote_sources[src] = remote_sources.get(src, 0) + 1
        remote_total = sum(remote_sources.values())
        local_total = len([u for u in unique_online_users if u.get("source") == "local"])
        self_total = len([u for u in unique_online_users if u.get("source") == "self"])
        print(f"[全局视图] 出块前统计: 总在线 {len(unique_online_users)} (本地客户端: {local_total}, 远程节点: {remote_total}, 本节点: {self_total})", flush=True)
        print(f"[全局视图] 有资格分奖: {online_count}, 等待分奖: {len(ineligible_users)}", flush=True)
        if remote_sources:
            for addr, count in remote_sources.items():
                print(f"[全局视图]   来自节点 {addr}: {count} 个用户", flush=True)

        if self.total_issued >= to_atomic(self.TOTAL_SUPPLY):
            print("[出块] 总量已达上限，停止出块", flush=True)
            return None

        remaining_supply = from_atomic(to_atomic(self.TOTAL_SUPPLY) - self.total_issued)
        block_reward = min(self.BLOCK_REWARD, remaining_supply)
        block_reward_atomic = to_atomic(block_reward)

        is_producer_eligible = self.server_address in [u["address"] for u in eligible_users]

        producer_reward_atomic = int(block_reward_atomic * PRODUCER_REWARD_SHARE)
        online_pool_atomic = block_reward_atomic - producer_reward_atomic

        eligible_for_pool = [u for u in eligible_users if u["address"] != self.server_address]
        pool_user_count = len(eligible_for_pool)

        if pool_user_count > 0:
            reward_per_user_atomic = online_pool_atomic // pool_user_count
            pool_burned = online_pool_atomic - (reward_per_user_atomic * pool_user_count)
        else:
            reward_per_user_atomic = 0
            pool_burned = online_pool_atomic

        if is_producer_eligible:
            producer_extra_atomic = producer_reward_atomic
            producer_burned = 0
        else:
            producer_extra_atomic = 0
            producer_burned = producer_reward_atomic
            print(f"[出块奖励] 出块节点 {self.server_address} 未满15区块，20%奖励 {format_amount(producer_reward_atomic)} XODE 将销毁", flush=True)

        burned = pool_burned + producer_burned

        prebuilt_recipients = []
        maturity = new_block_index + REWARD_CONFIRMATIONS

        if is_producer_eligible:
            prebuilt_recipients.append({
                "address": self.server_address,
                "amount": from_atomic(producer_extra_atomic),
                "amount_atomic": producer_extra_atomic,
                "is_producer": True
            })

        for user in eligible_for_pool:
            addr = user["address"]
            prebuilt_recipients.append({
                "address": addr,
                "amount": from_atomic(reward_per_user_atomic),
                "amount_atomic": reward_per_user_atomic,
                "is_producer": False
            })

        if burned > 0:
            prebuilt_recipients.append({
                "address": BURN_ADDRESS,
                "amount": from_atomic(burned),
                "amount_atomic": burned
            })

        reward_tx = {
            "total": block_reward,
            "online_count": online_count,
            "ineligible_count": len(ineligible_users),
            "producer_node": self.server_address,
            "producer_eligible": is_producer_eligible,
            "producer_reward": from_atomic(producer_extra_atomic),
            "producer_reward_atomic": producer_extra_atomic,
            "reward_per_user": from_atomic(reward_per_user_atomic),
            "reward_per_user_atomic": reward_per_user_atomic,
            "burned": from_atomic(burned),
            "burned_atomic": burned,
            "burn_address": BURN_ADDRESS,
            "recipients": prebuilt_recipients
        }

        with self.lock:
            self._clean_expired_txs()
            all_pending_txs = list(self.pending_transactions.values())
            block_transactions = self._select_txs_for_block(all_pending_txs)
            selected_hashes = {tx.get('tx_hash') for tx in block_transactions}
            dropped_txs = [tx for tx in all_pending_txs if tx.get('tx_hash') not in selected_hashes]
            if dropped_txs:
                print(f'[出块] {len(dropped_txs)} 笔交易因区块限制留待下一块打包', flush=True)

            latest = self.get_latest_block()
            difficulty = self.get_difficulty()

            objective_diff = self.get_difficulty_objective()
            if difficulty < objective_diff:
                print(f"[POW] 主观难度 {difficulty:.4f} 低于客观难度 {objective_diff:.4f}，使用客观难度挖矿", flush=True)
                difficulty = objective_diff

            import copy
            block_template = {
                "index": new_block_index,
                "timestamp": block_timestamp,
                "previous_hash": latest.hash,
                "reward_tx": copy.deepcopy(reward_tx),
                "transactions": copy.deepcopy(block_transactions),
                "difficulty": difficulty
            }

        nonce = 0
        target = difficulty_to_target(difficulty)
        start_time = time.time()
        mining_height = new_block_index
        found_hash = None
        last_ts_check = start_time

        print(f"[POW] 开始挖矿，位难度: {difficulty:.4f}，目标: < {hex(target)[:30]}...", flush=True)

        while self.running:
            if nonce > 0 and time.time() - last_ts_check >= 10:
                last_ts_check = time.time()
                current_mtp = self.get_median_time_past()
                new_ts = max(int(time.time()), current_mtp + 1)
                if new_ts != block_template["timestamp"]:
                    block_template["timestamp"] = new_ts
                    print(f"[POW] 挖矿中时间戳更新: {new_ts} (MTP: {current_mtp})", flush=True)

            test_hash = compute_block_hash(
                block_template["index"],
                block_template["timestamp"],
                block_template["previous_hash"],
                block_template["reward_tx"],
                block_template["transactions"],
                nonce,
                difficulty
            )

            if int(test_hash, 16) < target:
                found_hash = test_hash
                break

            nonce += 1
            if nonce % 50000 == 0:
                elapsed = time.time() - start_time
                self.local_hashrate = int(nonce / elapsed) if elapsed > 0 else 0
                with self.peer_lock:
                    max_peer_height = max(
                        (info.get("block_height", -1) for info in self.peer_sockets.values()),
                        default=-1
                    )
                if max_peer_height > mining_height:
                    print(f"[POW] 挖矿中断：检测到对等节点高度 {max_peer_height} > 本地 {mining_height}，可能存在更长链，放弃当前挖矿并同步", flush=True)
                    return None
                with self.lock:
                    if len(self.chain) != mining_height:
                        print(f"[POW] 挖矿中断：链已从 {mining_height} 增长到 {len(self.chain)}，其他节点已出块", flush=True)
                        return None
        else:
            return None

        final_mtp = self.get_median_time_past()
        if block_template["timestamp"] <= final_mtp:
            print(f"[POW] 挖矿期间链已增长，MTP 已更新为 {final_mtp}，时间戳 {block_template['timestamp']} 不再合法，放弃", flush=True)
            return None
        if block_template["timestamp"] > time.time() + 7200:
            print(f"[POW] 挖矿耗时过长，时间戳超出未来2小时限制，放弃", flush=True)
            return None

        elapsed = time.time() - start_time
        self.local_hashrate = int(nonce / elapsed) if elapsed > 0 else 0
        print(f"[POW] 区块 #{new_block_index} 挖矿成功！nonce={nonce}, hash={found_hash}, 耗时 {elapsed:.2f}s, 算力 {self.local_hashrate} h/s", flush=True)

        with self.chain_lock:
            with self.lock:
                if len(self.chain) != mining_height:
                    print(f"[POW] 区块 #{new_block_index} 已被其他节点挖出，放弃", flush=True)
                    return None

                executed_txs, failed_txs = self._execute_transactions_in_block(block_transactions)

                self._remove_confirmed_from_mempool(executed_txs)
                for tx in failed_txs:
                    fail_reason = tx.get("_fail_reason", "")
                    if fail_reason in ("nonce_expired", "insufficient_balance", "daily_limit"):
                        tx_hash = tx.get("tx_hash")
                        if tx_hash and tx_hash in self.pending_transactions:
                            del self.pending_transactions[tx_hash]
                            print(f"[Mempool] 移除永久失败交易 {tx_hash[:16]}... ({fail_reason})", flush=True)

                for tx in executed_txs:
                    tx["status"] = "confirmed"
                    tx["block_index"] = len(self.chain)
                    tx["confirmations"] = 0

                maturity = new_block_index + REWARD_CONFIRMATIONS

                if is_producer_eligible:
                    self.balances[self.server_address] = self.balances.get(self.server_address, 0) + producer_extra_atomic
                    if self.server_address not in self.pending_rewards:
                        self.pending_rewards[self.server_address] = []
                    self.pending_rewards[self.server_address].append({
                        "block_index": new_block_index,
                        "amount": producer_extra_atomic,
                        "maturity_block": maturity
                    })
                    print(f"[出块奖励] 出块节点 {self.server_address} 获得 {format_amount(producer_extra_atomic)} XODE (20%+dust)", flush=True)

                for user in eligible_for_pool:
                    addr = user["address"]
                    self.balances[addr] = self.balances.get(addr, 0) + reward_per_user_atomic
                    if addr not in self.pending_rewards:
                        self.pending_rewards[addr] = []
                    self.pending_rewards[addr].append({
                        "block_index": new_block_index,
                        "amount": reward_per_user_atomic,
                        "maturity_block": maturity
                    })

                if burned > 0:
                    self.balances[BURN_ADDRESS] = self.balances.get(BURN_ADDRESS, 0) + burned

                import copy
                new_block = Block(
                    index=block_template["index"],
                    timestamp=block_template["timestamp"],
                    previous_hash=block_template["previous_hash"],
                    reward_tx=copy.deepcopy(block_template["reward_tx"]),
                    transactions=copy.deepcopy(executed_txs),
                    nonce=nonce,
                    difficulty=difficulty,
                    hash=None
                )

                self.total_issued += to_atomic(block_reward)
                self.chain.append(new_block)
                self.block_inventory.add(new_block.hash)

        self._cleanup_pending_rewards()
        self._cleanup_pending_transfers()

        with self.lock:
            snapshot = {
                "chain": [block.to_dict() for block in self.chain],
                "balances": self.balances.copy(),
                "total_issued": self.total_issued,
                "transaction_history": {k: v[:] for k, v in self.transaction_history.items()},
                "address_nonces": self.address_nonces.copy(),
                "ip_bindings": {k: v.copy() for k, v in self.ip_bindings.items()},
                "address_first_seen_block": self.address_first_seen_block.copy(),
                "daily_transfer_stats": {k: v.copy() for k, v in self.daily_transfer_stats.items()},
                "pending_rewards": {k: v[:] for k, v in self.pending_rewards.items()},
                "pending_transfers": {k: v[:] for k, v in self.pending_transfers.items()},
                "pending_transactions": list(self.pending_transactions.values()),
                "saved_at": time.time(),
                "version": "xode"
            }
        self.save_data(snapshot)
        self.scan_address_history()

        self._broadcast_inv_for_block(new_block)
        self.broadcast_block(new_block, eligible_users, reward_per_user_atomic, burned, block_transactions, ineligible_users, producer_extra_atomic)

        remaining = from_atomic(to_atomic(self.TOTAL_SUPPLY) - self.total_issued)
        burned_total = self.get_burned_amount()

        print("", flush=True)
        print("=" * 60, flush=True)
        print("[新区块] #" + str(new_block.index), flush=True)
        print("  出块节点: " + self.server_address, flush=True)
        print("  哈希: " + new_block.hash, flush=True)
        print("  前一哈希: " + new_block.previous_hash[:30] + "...", flush=True)
        print("  时间: " + datetime.fromtimestamp(new_block.timestamp).strftime('%Y-%m-%d %H:%M:%S'), flush=True)
        print("  难度: " + f"{new_block.difficulty:.4f}", flush=True)
        print("  Nonce: " + str(new_block.nonce), flush=True)
        print("  全局在线人数: " + str(len(unique_online_users)), flush=True)
        print("  本地连接数: " + str(len(self.clients)), flush=True)
        print("  其他节点报告: " + str(len(unique_online_users) - len(self.clients) - 1) + " 个", flush=True)
        print("  有资格分奖: " + str(online_count), flush=True)
        if ineligible_users:
            print("  等待分奖(未满15区块): " + str(len(ineligible_users)), flush=True)
        print("  总奖励: " + format_amount(to_atomic(block_reward)) + " XODE", flush=True)
        if is_producer_eligible:
            print("  出块节点奖励(20%): " + format_amount(producer_extra_atomic) + " XODE -> " + self.server_address, flush=True)
        else:
            print("  出块节点奖励(20%): 0 XODE (未满15区块，已销毁)", flush=True)
        if pool_user_count > 0:
            print("  在线用户奖励(80%): " + format_amount(online_pool_atomic) + " XODE", flush=True)
            print("  有资格用户: " + str(pool_user_count) + " 人", flush=True)
            print("  每人基础分得: " + format_amount(reward_per_user_atomic) + " XODE", flush=True)
        else:
            print("  在线用户奖励(80%): 0 XODE (无资格用户)", flush=True)
        if burned > 0:
            print("  销毁: " + format_amount(burned) + " XODE -> " + BURN_ADDRESS, flush=True)
        if block_transactions:
            print("  打包交易: " + str(len(block_transactions)) + " 笔", flush=True)
        print("  已发行: " + format_amount(self.total_issued) + " / " + format_amount(to_atomic(self.TOTAL_SUPPLY)) + " XODE", flush=True)
        print("  剩余: " + format_amount(to_atomic(remaining)) + " XODE", flush=True)
        print("  累计销毁: " + format_amount(burned_total) + " XODE", flush=True)
        print("=" * 60, flush=True)

        return new_block

    def _broadcast_inv_for_block(self, block):
        inv_msg = {
            "type": "inv",
            "address": self.server_address,
            "items": [
                {"type": "block", "hash": block.hash, "index": block.index}
            ]
        }
        self._broadcast_to_peers(inv_msg)
        print(f"[P2P广播] 发送 inv，区块 #{block.index} {block.hash[:16]}...", flush=True)

    def broadcast_block(self, block, eligible_users, reward_per_user, burned, transactions, ineligible_users=None, producer_extra=0):
        ineligible_users = ineligible_users or []

        block_data = {
            "type": "new_block",
            "index": block.index,
            "hash": block.hash,
            "previous_hash": block.previous_hash,
            "timestamp": block.timestamp,
            "nonce": block.nonce,
            "difficulty": block.difficulty,
            "reward": {
                "total": block.reward_tx["total"],
                "online_count": block.reward_tx["online_count"],
                "ineligible_count": block.reward_tx.get("ineligible_count", 0),
                "producer_node": block.reward_tx.get("producer_node", ""),
                "producer_reward": block.reward_tx.get("producer_reward", 0),
                "producer_reward_atomic": block.reward_tx.get("producer_reward_atomic", 0),
                "per_user": from_atomic(reward_per_user),
                "per_user_atomic": reward_per_user,
                "burned": from_atomic(burned),
                "burned_atomic": burned,
                "burn_address": BURN_ADDRESS,
                "recipients": block.reward_tx.get("recipients", [])
            },
            "supply": {
                "issued": self.total_issued,
                "issued_atomic": self.total_issued,
                "total": to_atomic(self.TOTAL_SUPPLY),
                "total_atomic": to_atomic(self.TOTAL_SUPPLY),
                "remaining": to_atomic(self.TOTAL_SUPPLY) - self.total_issued,
                "remaining_atomic": to_atomic(self.TOTAL_SUPPLY) - self.total_issued,
                "burned_total": self.get_burned_amount(),
                "burned_total_atomic": self.get_burned_amount()
            },
            "transactions": transactions
        }

        message_bytes = encode_message(block_data)

        with self.lock:
            dead_sockets = []
            for sock in list(self.clients.keys()):
                try:
                    sock.sendall(message_bytes)
                except Exception:
                    dead_sockets.append(sock)
            for sock in dead_sockets:
                try:
                    self.remove_client(sock)
                except:
                    pass

        if eligible_users and reward_per_user > 0:
            for user in eligible_users:
                addr = user["address"]
                if user["socket"] is None:
                    continue
                balance = self.balances.get(addr, 0)
                user_reward = reward_per_user
                if addr == self.server_address and producer_extra > 0:
                    user_reward += producer_extra
                balance_update = {
                    "type": "balance_update",
                    "address": addr,
                    "balance": from_atomic(balance),
                    "balance_atomic": balance,
                    "block_index": block.index,
                    "reward": from_atomic(user_reward),
                    "reward_atomic": user_reward,
                    "is_producer": (addr == self.server_address and producer_extra > 0)
                }
                try:
                    user["socket"].sendall(encode_message(balance_update))
                except Exception:
                    pass

        for user in ineligible_users:
            if user["socket"] is None:
                continue
            addr = user["address"]
            first_seen = self.address_first_seen_block.get(addr, 0)
            remaining = BLOCKS_BEFORE_REWARD - (block.index - first_seen)
            notice = {
                "type": "reward_pending",
                "address": addr,
                "message": f"还需等待 {remaining} 个区块才参与分奖",
                "blocks_remaining": remaining,
                "first_seen_block": first_seen,
                "current_block": block.index
            }
            try:
                user["socket"].sendall(encode_message(notice))
            except Exception:
                pass

    def extract_json_messages(self, buffer):
        messages = []
        while True:
            idx = buffer.find(MAGIC)
            if idx == -1:
                break
            buffer = buffer[idx:]
            if len(buffer) < HEADER_SIZE:
                break
            length = struct.unpack('>I', buffer[4:8])[0]
            if length > MAX_PAYLOAD_SIZE:
                buffer = buffer[4:]
                continue
            if len(buffer) < HEADER_SIZE + length:
                break
            payload = buffer[HEADER_SIZE:HEADER_SIZE + length]
            buffer = buffer[HEADER_SIZE + length:]
            try:
                msg = json.loads(payload.decode('utf-8'))
                messages.append(msg)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        return messages, buffer

    def heartbeat_checker(self):
        while self.running:
            time.sleep(self.heartbeat_interval)
            current_time = time.time()
            dead_clients = []
            with self.lock:
                for client_socket, info in list(self.clients.items()):
                    last_ping = info.get("last_ping", 0)
                    if last_ping > 0 and current_time - last_ping > self.timeout:
                        print("[心跳] " + info['address'] + " 心跳超时，断开连接", flush=True)
                        dead_clients.append(client_socket)
                    elif current_time - info.get("connect_time", current_time) > 1800 and last_ping == 0:
                        print("[心跳] " + info['address'] + " 长时间无活动（30分钟），断开连接", flush=True)
                        dead_clients.append(client_socket)
            for client in dead_clients:
                try:
                    self.remove_client(client)
                except Exception as e:
                    print("清理超时客户端: " + str(e), flush=True)
            if dead_clients:
                self._save_client_list()

    def remove_client(self, client_socket):
        with self.lock:
            if client_socket not in self.clients:
                return
            address = self.clients[client_socket]["address"]
            client_ip = self.clients[client_socket]["addr"][0]
            del self.clients[client_socket]
            try:
                client_socket.close()
            except:
                pass

            still_connected = any(
                info["addr"][0] == client_ip
                for info in self.clients.values()
            )
            if not still_connected:
                unbind_time = time.time() + BIND_TIMEOUT
                if client_ip in self.ip_bindings:
                    self.ip_bindings[client_ip]["unbind_time"] = unbind_time
                else:
                    self.ip_bindings[client_ip] = {
                        "address": address,
                        "unbind_time": unbind_time,
                        "first_seen": time.time()
                    }
                print(f"[绑定] IP {client_ip} 与 {address} 的绑定将在 {BIND_TIMEOUT} 秒后解除", flush=True)

        self._save_client_list()
        print("[断开] " + address + " 已断开连接", flush=True)


    def _save_client_list(self):
        try:
            with self.lock:
                lines = []
                lines.append("=" * 60)
                lines.append(f"XODE 节点客户端列表")
                lines.append(f"更新时间: {datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')}")
                lines.append(f"节点地址: {self.server_address}")
                lines.append(f"当前在线客户端数: {len(self.clients)}")
                lines.append("=" * 60)
                if self.clients:
                    lines.append(f"{'序号':<4} {'地址':<24} {'IP':<16} {'端口':<6} {'连接时间':<20} {'最后心跳':<20} {'公钥前16位':<18}")
                    lines.append("-" * 110)
                    for idx, (sock, info) in enumerate(self.clients.items(), 1):
                        addr = info.get("address", "?")
                        ip = info.get("addr", ("?", "?"))[0]
                        port = info.get("addr", ("?", "?"))[1]
                        connect_time = info.get("connect_time", 0)
                        last_ping = info.get("last_ping", 0)
                        public_key = info.get("public_key", "")[:16]
                        connect_str = datetime.fromtimestamp(connect_time).strftime('%H:%M:%S') if connect_time else "?"
                        ping_str = datetime.fromtimestamp(last_ping).strftime('%H:%M:%S') if last_ping else "未心跳"
                        lines.append(f"{idx:<4} {addr:<24} {ip:<16} {port:<6} {connect_str:<20} {ping_str:<20} {public_key:<18}")
                else:
                    lines.append("(无在线客户端)")
                lines.append("=" * 60)
                content = "\n".join(lines) + "\n"
            with open(CLIENT_FILE, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception as e:
            print(f"[Client.txt] 保存失败: {e}", flush=True)

    def _notify_receiver_balance_update(self, to_addr, tx):
        with self.lock:
            receiver_socket = None
            for sock, info in self.clients.items():
                if info["address"] == to_addr:
                    receiver_socket = sock
                    break
            if receiver_socket:
                try:
                    balance = self.balances.get(to_addr, 0)
                    notify = {
                        "type": "balance_update",
                        "address": to_addr,
                        "balance": from_atomic(balance),
                        "balance_atomic": balance,
                        "reason": "transfer_received",
                        "from": tx["from"],
                        "amount": from_atomic(tx["amount"]),
                        "amount_atomic": tx["amount"],
                        "tx_hash": tx["tx_hash"],
                        "timestamp": time.time()
                    }
                    receiver_socket.sendall(encode_message(notify))
                    print(f"[通知] 已通知接收方 {to_addr} 余额更新", flush=True)
                except Exception as e:
                    print(f"[通知] 发送接收方通知失败: {e}", flush=True)

    def check_ip_binding(self, client_ip, xode_address):
        with self.lock:
            existing_first_seen = self.address_first_seen_block.get(xode_address)
            binding = self.ip_bindings.get(client_ip)

            if binding is None:
                if existing_first_seen is not None:
                    return True, None, "inherit"
                return True, None, "new"

            unbind_time = binding.get("unbind_time")
            is_expired = unbind_time is not None and time.time() >= unbind_time

            if is_expired:
                bound_addr = binding.get("address")
                if client_ip in self.ip_bindings:
                    del self.ip_bindings[client_ip]
                if bound_addr != xode_address:
                    is_other_online = any(
                        info["address"] == bound_addr
                        for info in self.clients.values()
                    )
                    if not is_other_online and bound_addr in self.address_first_seen_block:
                        del self.address_first_seen_block[bound_addr]
                        print(f"[冷却重置] {bound_addr} 绑定过期且不在线，冷却记录已清除", flush=True)
                if existing_first_seen is not None:
                    return True, None, "inherit"
                return True, None, "reset"

            bound_addr = binding.get("address")
            if bound_addr == xode_address:
                return True, None, "inherit"
            else:
                if unbind_time is not None:
                    remaining = max(0, int(unbind_time - time.time()))
                    return False, f"该IP已绑定地址 {bound_addr}，{remaining} 秒后才可更换", None
                else:
                    return False, f"该IP已有活跃连接（地址 {bound_addr}），请先断开当前连接后再换地址登录", None
    def _send_and_close(self, sock, msg_dict):
        try:
            sock.sendall(encode_message(msg_dict))
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass

    def handle_client(self, client_socket, addr):
        is_peer_socket = False
        client_ip = addr[0]
        try:
            try:
                client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            except (AttributeError, OSError):
                pass

            client_socket.settimeout(10)
            data = client_socket.recv(1024)
            client_socket.settimeout(None)

            if not data:
                return

            messages, remaining = decode_messages(data)
            if not messages:
                print("初始消息解析失败", flush=True)
                self._send_and_close(client_socket, {"type": "error", "error": "无法解析连接消息，请使用新版协议"})
                return

            init_data = messages[0]

            is_peer = all(k in init_data for k in ("port", "nonce", "block_height"))

            if is_peer:
                self._handle_inbound_peer(client_socket, addr, init_data)
                is_peer_socket = True
                return
            else:
                self._handle_inbound_wallet(client_socket, addr, init_data)

        except socket.timeout:
            print("[超时] 客户端 " + str(addr) + " 连接超时", flush=True)
        except Exception as e:
            print("[错误] 客户端处理 [" + str(addr) + "]: " + str(e), flush=True)
        finally:
            if not is_peer_socket:
                try:
                    if client_socket:
                        self.remove_client(client_socket)
                except Exception as e:
                    print("[错误] 移除客户端: " + str(e), flush=True)

    def _handle_inbound_peer(self, client_socket, addr, init_data):
        remote_nonce = init_data.get("nonce")

        if remote_nonce and remote_nonce == self.node_nonce:
            print(f"[P2P] 检测到自连接 from {addr}，nonce 匹配，断开", flush=True)
            self._send_and_close(client_socket, {"type": "error", "error": "connected to self"})
            return

        remote_port = init_data.get("port", 5555)
        remote_address = init_data.get("address", "")

        if remote_address and remote_address == self.server_address:
            print(f"[P2P] 检测到自连接 from {addr}，地址匹配 {self.server_address}，断开", flush=True)
            try:
                client_socket.close()
            except:
                pass
            return

        print(f"[P2P] 收到节点连接 from {addr}: {remote_address}", flush=True)

        remote_host = addr[0]
        if remote_host not in ('127.0.0.1', 'localhost'):
            self._add_known_peer(remote_host, remote_port, remote_address, init_data.get("is_producer", False), is_public=False)
            addr_tuple = (remote_host, remote_port)
            if addr_tuple not in self.peer_addrs:
                self.peer_addrs.append(addr_tuple)

        try:
            response = {
                "type": "version",
                "address": self.server_address,
                "public_key": self.server_public_key,
                "port": self.port,
                "is_producer": self.is_producer,
                "block_height": len(self.chain) - 1,
                "nonce": self.node_nonce
            }
            client_socket.sendall(encode_message(response))
        except Exception:
            try:
                client_socket.close()
            except:
                pass
            return

        with self.peer_lock:
            self.peer_sockets[client_socket] = {
                "host": remote_host,
                "port": remote_port,
                "connected": True,
                "address": remote_address,
                "is_producer": init_data.get("is_producer", False),
                "last_pong": time.time()
            }

        self._send_online_users_to_peer(client_socket)

        remote_height = init_data.get("block_height", -1)
        local_height = len(self.chain) - 1

        sync_msg = {
            "type": "node_chain_info",
            "address": self.server_address,
            "block_height": local_height,
            "latest_hash": self.chain[-1].hash if self.chain else "0" * 64
        }
        try:
            client_socket.sendall(encode_message(sync_msg))
        except Exception:
            pass

        with self.peer_lock:
            peers_list = []
            for addr_str, info in self.known_peers.items():
                if not info.get("is_public", False):
                    continue
                if ":" in addr_str:
                    host, port = addr_str.rsplit(":", 1)
                    peers_list.append({
                        "host": host,
                        "port": int(port),
                        "address": info.get("address"),
                        "is_public": True
                    })
        peers_msg = {
            "type": "node_peers",
            "address": self.server_address,
            "peers": peers_list
        }
        try:
            client_socket.sendall(encode_message(peers_msg))
            print(f"[P2P] 已向入向节点 {remote_address} 发送 {len(peers_list)} 个已知节点", flush=True)
        except Exception:
            pass

        if remote_height > local_height:
            print(f"[P2P同步] 新连接节点高度 {remote_height} > 本地 {local_height}，启动 headers 同步", flush=True)
            self._request_headers_from_peer(client_socket)
        elif local_height > remote_height >= 0:
            print(f"[P2P同步] 本地高度 {local_height} > 对方 {remote_height}，已发送 chain_info 供对方同步", flush=True)

        recv_thread = threading.Thread(
            target=self._handle_peer_connection,
            args=(client_socket, addr),
            daemon=True
        )
        recv_thread.start()

    def _handle_inbound_wallet(self, client_socket, addr, init_data):
        xode_address = None
        client_ip = addr[0]
        try:
            xode_address = init_data.get("address", "")
            public_key = init_data.get("public_key", "")

            if public_key and verify_public_key_address(public_key, xode_address):
                print("[连接] 客户端公钥验证通过: " + xode_address, flush=True)
            elif public_key:
                print("[拒绝] 公钥与地址不匹配: " + xode_address, flush=True)
                self._send_and_close(client_socket, {"type": "error", "error": "公钥与地址不匹配，地址可能已被伪造"})
                return
            else:
                print("[拒绝] 缺少公钥: " + str(xode_address), flush=True)
                self._send_and_close(client_socket, {"type": "error", "error": "连接消息缺少公钥字段"})
                return

            if self.is_valid_xode_address(xode_address):
                print("[连接] 客户端使用本地钱包地址: " + xode_address, flush=True)
            else:
                print("[拒绝] 地址格式无效: " + str(xode_address), flush=True)
                self._send_and_close(client_socket, {"type": "error", "error": "无效的XODE地址，请使用本地钱包生成的地址"})
                return
        except Exception:
            print("[拒绝] 初始消息解析失败", flush=True)
            self._send_and_close(client_socket, {"type": "error", "error": "无法解析连接消息，请发送有效的JSON地址"})
            return

        allowed, error_msg, cooldown_action = self.check_ip_binding(client_ip, xode_address)
        if not allowed:
            print(f"[拒绝] IP {client_ip} 尝试使用地址 {xode_address}，但 {error_msg}", flush=True)
            bind_info = self.ip_bindings.get(client_ip, {})
            unbind_time = bind_info.get("unbind_time")
            if unbind_time is not None:
                bind_remaining = max(0, int(unbind_time - time.time()))
            else:
                bind_remaining = BIND_TIMEOUT
            self._send_and_close(client_socket, {
                "type": "error",
                "error": f"IP绑定限制: {error_msg}",
                "bind_remaining": bind_remaining
            })
            return

        current_time = time.time()
        last_time = self.last_connect_time.get(xode_address, 0)
        if current_time - last_time < 180:
            print("[拒绝] " + xode_address + " 连接过于频繁，请 " + str(180 - int(current_time - last_time)) + " 秒后再试", flush=True)
            self._send_and_close(client_socket, {"type": "error", "error": "连接过于频繁，请稍后再试"})
            return

        with self.lock:
            is_known = xode_address in self.balances
            if is_known:
                print("[连接] 已知地址重新连接: " + xode_address, flush=True)

            self.last_connect_time[xode_address] = current_time
            current_height = len(self.chain) - 1

            if cooldown_action == "new":
                if xode_address in self.address_first_seen_block:
                    existing_first_seen = self.address_first_seen_block[xode_address]
                    blocks_waited = current_height - existing_first_seen
                    remaining = max(0, BLOCKS_BEFORE_REWARD - blocks_waited)
                    if remaining > 0:
                        print(f"[延迟分奖] 地址 {xode_address} 已有冷却记录（区块 #{existing_first_seen}），继承冷却，还需 {remaining} 区块", flush=True)
                    else:
                        print(f"[延迟分奖] 地址 {xode_address} 已有冷却记录（区块 #{existing_first_seen}），冷却已满，参与分奖", flush=True)
                else:
                    self.address_first_seen_block[xode_address] = current_height
                    print(f"[延迟分奖] 新用户 {xode_address} 首次记录于区块 #{current_height}，需等待 {BLOCKS_BEFORE_REWARD} 个区块", flush=True)

            elif cooldown_action == "reset":
                if xode_address in self.address_first_seen_block:
                    existing_first_seen = self.address_first_seen_block[xode_address]
                    blocks_waited = current_height - existing_first_seen
                    remaining = max(0, BLOCKS_BEFORE_REWARD - blocks_waited)
                    if remaining > 0:
                        print(f"[延迟分奖] 地址 {xode_address} 跨节点登录，继承冷却记录（区块 #{existing_first_seen}），还需 {remaining} 区块", flush=True)
                    else:
                        print(f"[延迟分奖] 地址 {xode_address} 跨节点登录，继承冷却记录（区块 #{existing_first_seen}），冷却已满，参与分奖", flush=True)
                else:
                    self.address_first_seen_block[xode_address] = current_height
                    print(f"[延迟分奖] 地址 {xode_address} IP绑定已过期，冷却重置，首次记录于区块 #{current_height}", flush=True)

            elif cooldown_action == "inherit":
                existing_first_seen = self.address_first_seen_block.get(xode_address)
                if existing_first_seen is None:
                    self.address_first_seen_block[xode_address] = current_height
                    print(f"[延迟分奖] 地址 {xode_address} 冷却记录异常，重新记录于区块 #{current_height}", flush=True)
                else:
                    blocks_waited = current_height - existing_first_seen
                    remaining = max(0, BLOCKS_BEFORE_REWARD - blocks_waited)
                    if remaining > 0:
                        print(f"[延迟分奖] 地址 {xode_address} 冷却继承中，已等待 {blocks_waited} 区块，还需 {remaining} 区块", flush=True)
                    else:
                        print(f"[延迟分奖] 地址 {xode_address} 冷却已满，参与分奖", flush=True)

            self.ip_bindings[client_ip] = {
                "address": xode_address,
                "unbind_time": None,
                "first_seen": self.ip_bindings.get(client_ip, {}).get("first_seen", current_time)
            }

            self.clients[client_socket] = {
                "address": xode_address,
                "addr": addr,
                "connect_time": time.time(),
                "last_ping": 0,
                "public_key": public_key
            }
            if xode_address not in self.balances:
                self.balances[xode_address] = 0

        print("[连接] " + xode_address + " (" + str(addr[0]) + ":" + str(addr[1]) + ") 已连接", flush=True)

        first_seen_block = self.address_first_seen_block.get(xode_address, 0)
        current_height = len(self.chain) - 1
        blocks_waited = current_height - first_seen_block
        blocks_remaining = max(0, BLOCKS_BEFORE_REWARD - blocks_waited)
        is_eligible = blocks_waited >= BLOCKS_BEFORE_REWARD

        try:
            total_bal = self.balances.get(xode_address, 0)
            spendable_bal = self.get_spendable_balance(xode_address)
            confirm = {
                "type": "connected",
                "address": xode_address,
                "balance": from_atomic(total_bal),
                "balance_atomic": total_bal,
                "spendable": from_atomic(spendable_bal),
                "spendable_atomic": spendable_bal,
                "locked": from_atomic(total_bal - spendable_bal),
                "locked_atomic": total_bal - spendable_bal,
                "pending_rewards": len(self.pending_rewards.get(xode_address, [])),
                "pending_transfers": len(self.pending_transfers.get(xode_address, [])),
                "block_height": current_height,
                "total_supply": self.TOTAL_SUPPLY,
                "total_supply_atomic": to_atomic(self.TOTAL_SUPPLY),
                "issued": self.total_issued,
                "issued_atomic": self.total_issued,
                "block_time": self.BLOCK_TIME,
                "block_reward": self.BLOCK_REWARD,
                "block_reward_atomic": to_atomic(self.BLOCK_REWARD),
                "burned_total": self.get_burned_amount(),
                "burned_total_atomic": self.get_burned_amount(),
                "transfer_fee": self.TRANSFER_FEE,
                "address_type": "wallet",
                "reward_eligible": is_eligible,
                "blocks_waited": blocks_waited,
                "blocks_remaining": blocks_remaining,
                "first_seen_block": first_seen_block,
                "ip_bound": True,
                "ip_bind_remaining": None
            }
            client_socket.sendall(encode_message(confirm))
        except Exception as e:
            print("[错误] 发送连接确认失败: " + str(e), flush=True)
            self.remove_client(client_socket)
            return

        self._save_client_list()

        buffer = b""
        while self.running:
            try:
                data = client_socket.recv(4096)
                if not data:
                    print("[断开] " + xode_address + " 主动断开", flush=True)
                    break

                with self.lock:
                    if client_socket in self.clients:
                        self.clients[client_socket]["last_ping"] = time.time()
                    else:
                        break

                buffer += data
                messages, remaining = self.extract_json_messages(buffer)
                buffer = remaining

                for msg_data in messages:
                    msg_type = msg_data.get("type", "")

                    if msg_type == "ping":
                        with self.lock:
                            if client_socket in self.clients:
                                self.clients[client_socket]["last_ping"] = time.time()
                        try:
                            client_socket.sendall(encode_message({"type": "pong"}))
                        except:
                            break
                        self._save_client_list()
                        continue

                    elif msg_type == "online_proof":
                        proof_signature = msg_data.get("signature", "")
                        proof_timestamp = msg_data.get("timestamp", 0)
                        proof_public_key = msg_data.get("public_key", "")

                        if not verify_public_key_address(proof_public_key, xode_address):
                            try:
                                client_socket.sendall(encode_message({
                                    "type": "online_proof_ack",
                                    "valid": False,
                                    "error": "公钥与地址不匹配"
                                }))
                            except:
                                pass
                            continue

                        current_time = time.time()
                        if abs(current_time - proof_timestamp) > self.ONLINE_PROOF_VALIDITY:
                            try:
                                client_socket.sendall(encode_message({
                                    "type": "online_proof_ack",
                                    "valid": False,
                                    "error": "证明已过期或时间偏差过大"
                                }))
                            except:
                                pass
                            continue

                        proof_message = f"XODE_ONLINE_PROOF:{xode_address}:{int(proof_timestamp)}"
                        if not verify_signature(proof_public_key, proof_message, proof_signature):
                            try:
                                client_socket.sendall(encode_message({
                                    "type": "online_proof_ack",
                                    "valid": False,
                                    "error": "签名验证失败"
                                }))
                            except:
                                pass
                            continue

                        with self.lock:
                            self.online_proofs[xode_address] = {
                                "signature": proof_signature,
                                "timestamp": proof_timestamp,
                                "public_key": proof_public_key
                            }

                        try:
                            client_socket.sendall(encode_message({
                                "type": "online_proof_ack",
                                "valid": True,
                                "expires_in": int(self.ONLINE_PROOF_VALIDITY - (current_time - proof_timestamp))
                            }))
                        except:
                            pass
                        print(f"[在线证明] 地址 {xode_address} 提交有效证明", flush=True)

                    elif msg_type == "transfer":
                        to_addr = msg_data.get("to", "")
                        amount = msg_data.get("amount", 0)
                        signature = msg_data.get("signature", "")
                        public_key = msg_data.get("public_key", "")
                        tx_timestamp = msg_data.get("timestamp", None)
                        tx_nonce = msg_data.get("nonce", None)

                        success, result = self.add_to_mempool(
                            xode_address, to_addr, amount,
                            signature=signature, public_key=public_key,
                            tx_timestamp=tx_timestamp, tx_nonce=tx_nonce
                        )

                        if success:
                            tx = result
                            response = {
                                "type": "transfer_result",
                                "success": True,
                                "from": xode_address,
                                "to": to_addr,
                                "amount": tx["amount"],
                                "amount_atomic": tx["amount_atomic"],
                                "fee": self.TRANSFER_FEE,
                                "balance": from_atomic(self.balances.get(xode_address, 0)),
                                "balance_atomic": self.balances.get(xode_address, 0),
                                "message": "交易已加入内存池，等待区块打包确认",
                                "pending": True,
                                "confirmations": 0,
                                "timestamp": time.time(),
                                "tx_hash": tx["tx_hash"]
                            }
                            print("[转账入池] " + xode_address + " -> " + to_addr + " " + format_amount(tx["amount_atomic"]) + " XODE (手续费 " + format_amount(tx["fee_atomic"]) + ")", flush=True)

                            tx_broadcast = {
                                "type": "node_tx",
                                "transaction": {
                                    "type": "transfer",
                                    "from": xode_address,
                                    "to": to_addr,
                                    "amount": tx["amount"],
                                    "amount_atomic": tx["amount_atomic"],
                                    "fee": tx["fee"],
                                    "fee_atomic": tx["fee_atomic"],
                                    "signature": signature,
                                    "public_key": public_key,
                                    "timestamp": tx_timestamp,
                                    "nonce": tx_nonce,
                                    "tx_hash": tx["tx_hash"]
                                },
                                "address": self.server_address
                            }
                            if tx["tx_hash"] not in self.broadcasted_tx_hashes:
                                self.broadcasted_tx_hashes.add(tx["tx_hash"])
                                self._broadcast_to_peers(tx_broadcast)
                        else:
                            response = {
                                "type": "transfer_result",
                                "success": False,
                                "error": result
                            }

                        try:
                            client_socket.sendall(encode_message(response))
                        except Exception as e:
                            print("[错误] 发送转账结果失败: " + str(e), flush=True)

                    elif msg_type == "get_balance":
                        query_addr = msg_data.get("address", xode_address)
                        balance = self.balances.get(query_addr, 0)
                        spendable = self.get_spendable_balance(query_addr)
                        locked = balance - spendable
                        response = {
                            "type": "balance",
                            "address": query_addr,
                            "balance": from_atomic(balance),
                            "balance_atomic": balance,
                            "spendable": from_atomic(spendable),
                            "spendable_atomic": spendable,
                            "locked": from_atomic(locked),
                            "locked_atomic": locked,
                            "pending_rewards": len(self.pending_rewards.get(query_addr, []))
                        }
                        try:
                            client_socket.sendall(encode_message(response))
                        except Exception as e:
                            print("[错误] 发送余额失败: " + str(e), flush=True)

                    elif msg_type == "get_chain":
                        try:
                            chain_data = []
                            for block in self.chain:
                                chain_data.append({
                                    "index": block.index,
                                    "hash": block.hash,
                                    "previous_hash": block.previous_hash,
                                    "timestamp": block.timestamp,
                                    "nonce": block.nonce,
                                    "difficulty": block.difficulty,
                                    "reward": block.reward_tx,
                                    "transactions": block.transactions
                                })
                            response = {
                                "type": "chain_data",
                                "blocks": chain_data,
                                "total_blocks": len(chain_data),
                                "latest_hash": self.chain[-1].hash
                            }
                            client_socket.sendall(encode_message(response))
                        except Exception as e:
                            print("[错误] 发送链数据失败: " + str(e), flush=True)

                    elif msg_type == "get_blocks":
                        try:
                            start_idx = msg_data.get("start", 0)
                            end_idx = msg_data.get("end", len(self.chain))
                            if end_idx - start_idx > 10:
                                end_idx = start_idx + 10
                            chain_data = []
                            for i in range(start_idx, min(end_idx, len(self.chain))):
                                block = self.chain[i]
                                chain_data.append({
                                    "index": block.index,
                                    "hash": block.hash,
                                    "previous_hash": block.previous_hash,
                                    "timestamp": block.timestamp,
                                    "nonce": block.nonce,
                                    "difficulty": block.difficulty,
                                    "reward": block.reward_tx,
                                    "transactions": block.transactions
                                })
                            response = {
                                "type": "blocks_range",
                                "blocks": chain_data,
                                "start": start_idx,
                                "end": start_idx + len(chain_data),
                                "total_blocks": len(self.chain),
                                "latest_hash": self.chain[-1].hash
                            }
                            client_socket.sendall(encode_message(response))
                        except Exception as e:
                            print("[错误] 发送区块范围失败: " + str(e), flush=True)

                    elif msg_type == "get_stats":
                        online = len(self.clients)
                        eligible_count = sum(
                            1 for u in self.get_online_users()
                            if self.is_address_eligible_for_reward(u["address"])
                        )
                        ineligible_count = online - eligible_count
                        response = {
                            "type": "stats",
                            "block_height": len(self.chain) - 1,
                            "total_issued": self.total_issued,
                            "total_issued_atomic": self.total_issued,
                            "total_supply": self.TOTAL_SUPPLY,
                            "total_supply_atomic": to_atomic(self.TOTAL_SUPPLY),
                            "remaining": from_atomic(to_atomic(self.TOTAL_SUPPLY) - self.total_issued),
                            "remaining_atomic": to_atomic(self.TOTAL_SUPPLY) - self.total_issued,
                            "burned_total": self.get_burned_amount(),
                            "burned_total_atomic": self.get_burned_amount(),
                            "burn_address": BURN_ADDRESS,
                            "online_users": online,
                            "eligible_users": eligible_count,
                            "ineligible_users": ineligible_count,
                            "block_time": self.BLOCK_TIME,
                            "block_reward": self.BLOCK_REWARD,
                            "transfer_fee": self.TRANSFER_FEE,
                            "pending_tx": len(self.pending_transactions),
                            "blocks_before_reward": BLOCKS_BEFORE_REWARD,
                            "difficulty": self.chain[-1].difficulty if self.chain else self.INITIAL_DIFFICULTY
                        }
                        try:
                            client_socket.sendall(encode_message(response))
                        except Exception as e:
                            print("[错误] 发送统计失败: " + str(e), flush=True)

                    elif msg_type == "get_history":
                        query_addr = msg_data.get("address", xode_address)
                        history = self.transaction_history.get(query_addr, [])
                        for block in self.chain:
                            for tx in block.transactions:
                                if tx.get("from") == query_addr or tx.get("to") == query_addr:
                                    if tx not in history:
                                        history.append(tx)
                        display_history = []
                        for tx in history[-50:]:
                            display_tx = tx.copy()
                            current_height = len(self.chain) - 1
                            tx_block = display_tx.get("block_index")
                            if tx_block is not None:
                                confirmations = max(0, current_height - tx_block + 1)
                            else:
                                confirmations = 0
                            display_tx["confirmations"] = confirmations
                            tx_type = display_tx.get("type", "transfer")
                            is_reward = tx_type == "reward" or display_tx.get("from") == "SYSTEM" or display_tx.get("from") == "GENESIS"
                            if is_reward:
                                display_tx["required_confirmations"] = REWARD_CONFIRMATIONS
                                display_tx["is_mature"] = confirmations >= REWARD_CONFIRMATIONS
                                if not display_tx["is_mature"]:
                                    display_tx["status"] = "immature"
                            else:
                                display_tx["required_confirmations"] = TX_CONFIRMATIONS
                                display_tx["is_mature"] = confirmations >= TX_CONFIRMATIONS
                                if tx_block is not None and not display_tx["is_mature"]:
                                    display_tx["status"] = "confirming"

                            is_incoming_transfer = (display_tx.get("to") == query_addr and 
                                                    display_tx.get("from") not in ("SYSTEM", "GENESIS", None))
                            if is_incoming_transfer and tx_block is not None:
                                transfer_maturity = tx_block + TX_CONFIRMATIONS
                                is_transfer_mature = current_height >= transfer_maturity
                                if not is_transfer_mature:
                                    display_tx["required_confirmations"] = TX_CONFIRMATIONS
                                    display_tx["is_mature"] = False
                                    display_tx["status"] = "confirming"
                                    display_tx["maturity_block"] = transfer_maturity
                                    display_tx["blocks_until_mature"] = transfer_maturity - current_height

                            if "amount" in display_tx:
                                display_tx["amount"] = from_atomic(display_tx["amount"])
                            if "fee" in display_tx:
                                display_tx["fee"] = from_atomic(display_tx["fee"])
                            display_history.append(display_tx)
                        response = {
                            "type": "history",
                            "address": query_addr,
                            "transactions": display_history,
                            "total": len(history)
                        }
                        try:
                            client_socket.sendall(encode_message(response))
                        except Exception as e:
                            print("[错误] 发送历史记录失败: " + str(e), flush=True)

                    elif msg_type == "get_tx_status":
                        tx_hash_query = msg_data.get("tx_hash", "")
                        if not tx_hash_query:
                            response = {
                                "type": "tx_status",
                                "found": False,
                                "error": "缺少 tx_hash 参数"
                            }
                        else:
                            found_tx = None
                            found_block = None
                            if tx_hash_query in self.pending_transactions:
                                found_tx = self.pending_transactions[tx_hash_query]
                                found_block = None
                            else:
                                for block in self.chain:
                                    for tx in block.transactions:
                                        if tx.get("tx_hash") == tx_hash_query:
                                            found_tx = tx
                                            found_block = block
                                            break
                                    if found_tx:
                                        break

                            if found_tx:
                                current_height = len(self.chain) - 1
                                tx_block = found_tx.get("block_index")
                                if tx_block is not None:
                                    confirmations = max(0, current_height - tx_block + 1)
                                else:
                                    confirmations = 0

                                response = {
                                    "type": "tx_status",
                                    "found": True,
                                    "tx_hash": tx_hash_query,
                                    "status": found_tx.get("status", "unknown"),
                                    "confirmations": confirmations,
                                    "block_index": found_block.index if found_block else None,
                                    "block_hash": found_block.hash if found_block else None,
                                    "from": found_tx.get("from"),
                                    "to": found_tx.get("to"),
                                    "amount": from_atomic(found_tx.get("amount_atomic", 0)),
                                    "amount_atomic": found_tx.get("amount_atomic", 0),
                                    "fee": from_atomic(found_tx.get("fee_atomic", 0)),
                                    "fee_atomic": found_tx.get("fee_atomic", 0),
                                    "timestamp": found_tx.get("timestamp"),
                                    "nonce": found_tx.get("nonce")
                                }
                            else:
                                response = {
                                    "type": "tx_status",
                                    "found": False,
                                    "tx_hash": tx_hash_query,
                                    "error": "未找到该交易"
                                }
                        try:
                            client_socket.sendall(encode_message(response))
                        except Exception as e:
                            print("[错误] 发送交易状态失败: " + str(e), flush=True)

                    elif msg_type == "get_rankings":
                        limit = msg_data.get("limit", 100)
                        valid_balances = {
                            addr: bal for addr, bal in self.balances.items()
                            if addr != BURN_ADDRESS and bal > 0
                        }
                        sorted_items = sorted(
                            valid_balances.items(),
                            key=lambda x: x[1],
                            reverse=True
                        )[:limit]
                        rankings = [
                            {"rank": i+1, "address": addr, "balance": from_atomic(bal), "balance_atomic": bal}
                            for i, (addr, bal) in enumerate(sorted_items)
                        ]
                        response = {
                            "type": "rankings",
                            "rankings": rankings,
                            "total_addresses": len(valid_balances),
                            "my_address": xode_address,
                            "my_balance": from_atomic(self.balances.get(xode_address, 0)),
                            "my_balance_atomic": self.balances.get(xode_address, 0)
                        }
                        try:
                            client_socket.sendall(encode_message(response))
                        except Exception as e:
                            print("[错误] 发送排行榜失败: " + str(e), flush=True)

                    elif msg_type == "get_mining_template":
                        producer_address = msg_data.get("producer_address", xode_address)
                        template, err = self._build_mining_template(producer_address)
                        if template:
                            response = {
                                "type": "mining_template",
                                "template": template,
                                "target_hex": hex(difficulty_to_target(template["difficulty"]))
                            }
                        else:
                            response = {
                                "type": "mining_template",
                                "error": err or "Failed to build template"
                            }
                        try:
                            client_socket.sendall(encode_message(response))
                        except Exception as e:
                            print(f"[错误] 发送挖矿模板失败: {e}", flush=True)

                    elif msg_type == "submit_block":
                        block_data = msg_data.get("block", {})
                        success = self._try_connect_block(block_data)
                        response = {
                            "type": "submit_block_result",
                            "success": success,
                            "hash": block_data.get("hash", ""),
                            "index": block_data.get("index", -1)
                        }
                        try:
                            client_socket.sendall(encode_message(response))
                        except Exception as e:
                            print(f"[错误] 发送提交结果失败: {e}", flush=True)
                        if success:
                            print(f"[P2P] 客户端 {xode_address} 提交区块 #{block_data.get('index')} 成功", flush=True)
                        else:
                            print(f"[P2P] 客户端 {xode_address} 提交区块 #{block_data.get('index')} 失败", flush=True)

            except ConnectionResetError:
                print("[断开] " + xode_address + " 连接重置", flush=True)
                break
            except ConnectionAbortedError:
                print("[断开] " + xode_address + " 连接中止", flush=True)
                break
            except OSError as e:
                print("[断开] " + xode_address + " OS错误: " + str(e), flush=True)
                break
            except Exception as e:
                print("[错误] 处理消息 [" + xode_address + "]: " + str(e), flush=True)
                break


    def _load_known_peers(self):
        if not os.path.exists(self.peers_file):
            return
        try:
            with open(self.peers_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            loaded_peers = data.get("peers", {})
            public_host = self._get_public_host()

            for addr_str, info in loaded_peers.items():
                if info.get("address") == self.server_address:
                    continue
                if addr_str == f"{public_host}:{self.port}":
                    continue
                if addr_str == f"{self.host}:{self.port}":
                    continue
                if addr_str.startswith('127.0.0.1:') or addr_str.startswith('localhost:'):
                    continue

                self.known_peers[addr_str] = info
                if "is_public" not in self.known_peers[addr_str]:
                    self.known_peers[addr_str]["is_public"] = True
                if ":" in addr_str:
                    host, port = addr_str.rsplit(":", 1)
                    addr_tuple = (host, int(port))
                    if addr_tuple not in self.peer_addrs:
                        self.peer_addrs.append(addr_tuple)

            print(f"[P2P] 已加载 {len(self.known_peers)} 个已知对等节点", flush=True)
        except Exception as e:
            print(f"[P2P] 加载对等节点文件失败: {e}", flush=True)

    def _get_public_host(self):
        if self.announce_ip:
            return self.announce_ip
        if self.host not in ('0.0.0.0', '127.0.0.1', 'localhost'):
            return self.host
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return '127.0.0.1'

    def _ensure_self_in_peers_txt(self):
        if not self.server_address:
            return
        try:
            if not os.path.exists(PEERS_CONFIG_FILE):
                return

            existing_lines = []
            with open(PEERS_CONFIG_FILE, 'r', encoding='utf-8') as f:
                existing_lines = f.readlines()

            public_host = self._get_public_host()
            self_hostport = f"{public_host}:{self.port}"

            filtered = []
            removed = False
            for line in existing_lines:
                stripped = line.strip()
                if not stripped:
                    continue
                parts = stripped.split()
                if len(parts) > 1 and parts[1] == self.server_address:
                    removed = True
                    continue
                if parts[0] == self_hostport:
                    removed = True
                    continue
                if parts[0].startswith('127.0.0.1:') or parts[0].startswith('localhost:'):
                    removed = True
                    continue
                filtered.append(stripped + "\n")

            if removed:
                with open(PEERS_CONFIG_FILE, 'w', encoding='utf-8') as f:
                    for line in filtered:
                        f.write(line)
                print(f"[P2P种子] 已从 peers.txt 清理本节点记录", flush=True)
        except Exception as e:
            print(f"[P2P种子] 清理 peers.txt 自身记录失败: {e}", flush=True)

    def _save_peers_to_txt(self):
        if not self.server_address:
            return
        try:
            public_host = self._get_public_host()
            self_hostport = f"{public_host}:{self.port}"

            peer_lines = []
            seen = set()
            for addr_str, info in self.known_peers.items():
                if addr_str == self_hostport:
                    continue
                if info.get("address") == self.server_address:
                    continue
                if not info.get("is_public", False):
                    continue
                if addr_str in seen:
                    continue
                seen.add(addr_str)
                address = info.get("address", "")
                is_producer = info.get("is_producer", False)
                mode = "producer" if is_producer else "sync"
                if address:
                    peer_lines.append(f"{addr_str} {address} {mode}")
                else:
                    peer_lines.append(f"{addr_str} {mode}")

            with open(PEERS_CONFIG_FILE, 'w', encoding='utf-8') as f:
                for line in peer_lines:
                    f.write(line + "\n")

            if peer_lines:
                print(f"[P2P种子] 已保存 {len(peer_lines)} 个公网对等节点到 peers.txt", flush=True)
        except Exception as e:
            print(f"[P2P种子] 保存对等节点到 peers.txt 失败: {e}", flush=True)

    def _load_seed_peers(self):
        self._ensure_self_in_peers_txt()

        if not os.path.exists(PEERS_CONFIG_FILE):
            default_txt = ""
            try:
                with open(PEERS_CONFIG_FILE, 'w', encoding='utf-8') as f:
                    f.write(default_txt)
                print(f"[P2P] 已创建默认种子节点配置文件: {PEERS_CONFIG_FILE}，请手动编辑添加种子节点", flush=True)
            except Exception as e:
                print(f"[P2P] 创建 {PEERS_CONFIG_FILE} 失败: {e}", flush=True)
            return

        loaded = 0
        try:
            with open(PEERS_CONFIG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split()
                    host_port = parts[0]
                    address = None
                    is_producer = False

                    if len(parts) == 2:
                        if parts[1].lower() in ("producer", "sync"):
                            is_producer = parts[1].lower() == "producer"
                        else:
                            address = parts[1]
                    elif len(parts) >= 3:
                        address = parts[1]
                        mode = parts[2].lower()
                        is_producer = mode == "producer"

                    if ":" in host_port:
                        host, port_str = host_port.rsplit(":", 1)
                        try:
                            port = int(port_str)
                        except ValueError:
                            port = self.port
                    else:
                        host = host_port
                        port = self.port

                    if not host:
                        continue

                    public_host = self._get_public_host()
                    is_self = False
                    if host in ('127.0.0.1', 'localhost', '0.0.0.0', self.host) and port == self.port:
                        is_self = True
                    if host == public_host and port == self.port:
                        is_self = True
                    if address and address == self.server_address:
                        is_self = True
                    if is_self:
                        continue

                    addr_tuple = (host, port)
                    if addr_tuple not in self.peer_addrs:
                        self.peer_addrs.append(addr_tuple)
                        loaded += 1

                    addr_str = f"{host}:{port}"
                    if addr_str not in self.known_peers:
                        self.known_peers[addr_str] = {
                            "last_seen": 0,
                            "first_seen": time.time(),
                            "address": address,
                            "is_producer": is_producer
                        }
                    else:
                        if address:
                            self.known_peers[addr_str]["address"] = address
                        self.known_peers[addr_str]["is_producer"] = is_producer

                    info = f"{host}:{port}"
                    if address:
                        info += f" ({address[:20]}...)"
                    mode_str = "producer" if is_producer else "sync"
                    info += f" [{mode_str}]"
                    print(f"[P2P种子] 从 peers.txt 加载: {info}", flush=True)

            if loaded > 0:
                print(f"[P2P种子] 共加载 {loaded} 个种子节点到连接队列", flush=True)
            self._save_known_peers()
            self._save_peers_to_txt()
        except Exception as e:
            print(f"[P2P种子] 加载 {PEERS_CONFIG_FILE} 失败: {e}", flush=True)

    def _mark_peer_failed(self, host, port, reason=""):
        addr_str = f"{host}:{port}"
        if addr_str in self.known_peers:
            self.known_peers[addr_str]["fail_count"] = self.known_peers[addr_str].get("fail_count", 0) + 1
            fail_count = self.known_peers[addr_str]["fail_count"]
            print(f"[P2P] 节点 {addr_str} 失败次数: {fail_count} ({reason})", flush=True)
            if fail_count >= 3:
                self._remove_peer(host, port, reason="多次失败(>=3)")
        else:
            self._remove_peer_addr(host, port)

    def _remove_peer(self, host, port, reason=""):
        addr_str = f"{host}:{port}"
        removed = False
        if addr_str in self.known_peers:
            del self.known_peers[addr_str]
            removed = True
            print(f"[P2P] 从已知节点移除 {addr_str} ({reason})", flush=True)
        if (host, port) in self.peer_addrs:
            self.peer_addrs.remove((host, port))
            removed = True
        if removed:
            self._save_known_peers()
            self._save_peers_to_txt()

    def _remove_peer_addr(self, host, port):
        if (host, port) in self.peer_addrs:
            self.peer_addrs.remove((host, port))

    def _remove_self_from_peers(self):
        self_addr = f"{self.host}:{self.port}"
        to_remove = []
        for addr_str in list(self.known_peers.keys()):
            if addr_str == self_addr:
                to_remove.append(addr_str)
                continue
            info = self.known_peers[addr_str]
            if info.get("address") == self.server_address:
                to_remove.append(addr_str)
        for addr_str in to_remove:
            del self.known_peers[addr_str]
            print(f"[P2P] 从已知节点移除自身: {addr_str}", flush=True)
        if to_remove:
            self._save_known_peers()

    def _save_known_peers(self):
        try:
            data = {
                "peers": self.known_peers,
                "saved_at": time.time(),
                "address": self.server_address
            }
            with open(self.peers_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[P2P] 保存对等节点文件失败: {e}", flush=True)

    def _add_known_peer(self, host, port, address=None, is_producer=None, is_public=None):
        addr_str = f"{host}:{port}"
        if host in ('127.0.0.1', 'localhost', '0.0.0.0', self.host):
            if port == self.port:
                return False
        if address and address == self.server_address:
            return False

        if addr_str in self.known_peers:
            info = self.known_peers[addr_str]
            changed = False
            info["last_seen"] = time.time()

            if address and info.get("address") != address:
                old_addr = info.get("address", "unknown")
                info["address"] = address
                changed = True
                print(f"[P2P] 节点 {addr_str} 地址更新: {old_addr} -> {address}", flush=True)

            if is_producer is not None and info.get("is_producer") != is_producer:
                old_mode = "producer" if info.get("is_producer", False) else "sync"
                new_mode = "producer" if is_producer else "sync"
                info["is_producer"] = is_producer
                changed = True
                print(f"[P2P] 节点 {addr_str} 模式更新: {old_mode} -> {new_mode}", flush=True)

            if is_public is not None:
                if is_public and not info.get("is_public", False):
                    info["is_public"] = True
                    changed = True
                    print(f"[P2P] 节点 {addr_str} 标记为公网节点", flush=True)
                elif not is_public and info.get("is_public") is None:
                    info["is_public"] = False
                    changed = True

            if changed:
                self._save_known_peers()
                self._save_peers_to_txt()
            return False

        self.known_peers[addr_str] = {
            "last_seen": time.time(),
            "address": address,
            "first_seen": time.time(),
            "is_producer": is_producer if is_producer is not None else False,
            "fail_count": 0,
            "is_public": is_public if is_public is not None else False
        }
        self._save_known_peers()
        self._save_peers_to_txt()
        mode_str = "producer" if (is_producer if is_producer is not None else False) else "sync"
        public_str = "公网" if (is_public if is_public is not None else False) else "非公网"
        print(f"[P2P] 新增对等节点: {addr_str} (地址: {address or 'unknown'}, 模式: {mode_str}, 类型: {public_str})", flush=True)
        return True

    def _connect_to_peer(self, host, port):
        if host in ('127.0.0.1', 'localhost', '0.0.0.0', self.host) and port == self.port:
            return False
        public_host = self._get_public_host()
        if host == public_host and port == self.port:
            return False
        with self.peer_lock:
            for info in self.peer_sockets.values():
                if info.get("host") == host and info.get("port") == port:
                    return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            sock.connect((host, port))
            sock.settimeout(None)

            init_msg = {
                "type": "node_version",
                "address": self.server_address,
                "public_key": self.server_public_key,
                "port": self.port,
                "is_producer": self.local_hashrate > 0,
                "block_height": len(self.chain) - 1,
                "nonce": self.node_nonce
            }
            sock.sendall(encode_message(init_msg))

            with self.peer_lock:
                self.peer_sockets[sock] = {
                    "host": host,
                    "port": port,
                    "connected": True,
                    "address": "",
                    "last_pong": time.time()
                }

            print(f"[P2P] 已连接到节点 {host}:{port}", flush=True)
            self._add_known_peer(host, port, is_public=True)
            self._save_peers_to_txt()

            self._send_online_users_to_peer(sock)

            recv_thread = threading.Thread(
                target=self._handle_peer_connection,
                args=(sock, (host, port)),
                daemon=True
            )
            recv_thread.start()
            return True
        except Exception as e:
            print(f"[P2P] 连接节点 {host}:{port} 失败: {e}", flush=True)
            self._mark_peer_failed(host, port, reason=f"连接失败: {e}")
            return False

    def _handle_peer_connection(self, sock, addr):
        buffer = b""
        while self.running:
            try:
                data = sock.recv(65536)
                if not data:
                    break
                buffer += data
                messages, buffer = decode_messages(buffer)
                for msg in messages:
                    self._handle_peer_message(sock, msg)
            except Exception as e:
                if self.running:
                    print(f"[P2P] 节点连接错误 {addr}: {e}", flush=True)
                break

        with self.peer_lock:
            info = self.peer_sockets.pop(sock, None)
        try:
            sock.close()
        except:
            pass
        if info and self.running:
            host = info.get("host")
            port = info.get("port")
            print(f"[P2P] 节点 {host}:{port} 断开", flush=True)
            self._mark_peer_failed(host, port, reason="连接断开")
        else:
            print(f"[P2P] 节点 {addr} 断开", flush=True)

    def _handle_peer_message(self, sock, msg):
        msg_type = msg.get("type", "")

        if msg_type == "version":
            remote_nonce = msg.get("nonce")
            remote_address = msg.get("address", "")

            if remote_nonce and remote_nonce == self.node_nonce:
                print(f"[P2P] 检测到自连接（出向），nonce 匹配，断开", flush=True)
                with self.peer_lock:
                    if sock in self.peer_sockets:
                        del self.peer_sockets[sock]
                try:
                    sock.close()
                except:
                    pass
                return

            remote_host = None
            with self.peer_lock:
                if sock in self.peer_sockets:
                    remote_host = self.peer_sockets[sock].get("host")
            if remote_host:
                existing_inbound = None
                with self.peer_lock:
                    for existing_sock, info in list(self.peer_sockets.items()):
                        if existing_sock != sock and info.get("host") == remote_host:
                            existing_inbound = existing_sock
                            break
                if existing_inbound:
                    print(f"[P2P] 检测到重复连接 {remote_host}，断开 outbound", flush=True)
                    with self.peer_lock:
                        if sock in self.peer_sockets:
                            del self.peer_sockets[sock]
                    try:
                        sock.close()
                    except:
                        pass
                    return

            remote_height = msg.get("block_height", -1)
            with self.peer_lock:
                if sock in self.peer_sockets:
                    self.peer_sockets[sock]["address"] = remote_address
                    self.peer_sockets[sock]["is_producer"] = False
                    self.peer_sockets[sock]["hashrate"] = 0
                    if remote_height >= 0:
                        self.peer_sockets[sock]["block_height"] = remote_height

            remote_host = None
            remote_port = None
            with self.peer_lock:
                if sock in self.peer_sockets:
                    remote_host = self.peer_sockets[sock].get("host")
                    remote_port = self.peer_sockets[sock].get("port")
            if remote_host and remote_port:
                self._add_known_peer(remote_host, remote_port, remote_address, msg.get("is_producer", False))

            sync_msg = {
                "type": "node_chain_info",
                "address": self.server_address,
                "block_height": len(self.chain) - 1,
                "latest_hash": self.chain[-1].hash if self.chain else "0" * 64
            }
            try:
                sock.sendall(encode_message(sync_msg))
            except:
                pass
            with self.peer_lock:
                peers_list = []
                for addr_str, info in self.known_peers.items():
                    if not info.get("is_public", False):
                        continue
                    if ":" in addr_str:
                        host, port = addr_str.rsplit(":", 1)
                        peers_list.append({
                            "host": host,
                            "port": int(port),
                            "address": info.get("address"),
                            "is_producer": info.get("is_producer", False),
                            "is_public": True
                        })
            peers_msg = {
                "type": "node_peers",
                "address": self.server_address,
                "peers": peers_list
            }
            try:
                sock.sendall(encode_message(peers_msg))
                print(f"[P2P] 已向节点 {msg.get('address', 'unknown')} 发送 {len(peers_list)} 个已知节点", flush=True)
            except:
                pass
            self._send_online_users_to_peer(sock)

        elif msg_type == "node_ping":
            try:
                pong_msg = {"type": "node_pong", "address": self.server_address, "timestamp": time.time()}
                sock.sendall(encode_message(pong_msg))
            except:
                pass

        elif msg_type == "node_peers":
            remote_peers = msg.get("peers", [])
            new_count = 0
            for peer_info in remote_peers:
                host = peer_info.get("host")
                port = peer_info.get("port")
                peer_address = peer_info.get("address")
                peer_is_producer = peer_info.get("is_producer", False)
                if host and port:
                    added = self._add_known_peer(host, port, peer_address, peer_is_producer)
                    if not added:
                        continue
                    new_count += 1
                    addr_tuple = (host, port)
                    with self.peer_lock:
                        already_connected = any(
                            info.get("host") == host and info.get("port") == port
                            for info in self.peer_sockets.values()
                        )
                    if not already_connected and addr_tuple not in self.peer_addrs:
                        self.peer_addrs.append(addr_tuple)
                        threading.Thread(target=self._connect_to_peer, args=(host, port), daemon=True).start()
            if new_count > 0:
                print(f"[P2P] 从节点 {msg.get('address', 'unknown')} 发现 {new_count} 个新节点", flush=True)
                self._save_peers_to_txt()
            self._remove_self_from_peers()

        elif msg_type == "node_pong":
            with self.peer_lock:
                if sock in self.peer_sockets:
                    self.peer_sockets[sock]["last_pong"] = time.time()
                    self.peer_sockets[sock]["last_pong_time"] = msg.get("timestamp", time.time())
                    host = self.peer_sockets[sock].get("host")
                    port = self.peer_sockets[sock].get("port")
                    addr_str = f"{host}:{port}"
                    if addr_str in self.known_peers:
                        if self.known_peers[addr_str].get("fail_count", 0) > 0:
                            self.known_peers[addr_str]["fail_count"] = 0
                            print(f"[P2P] 节点 {addr_str} 恢复在线，重置失败计数", flush=True)
                            self._save_known_peers()

        elif msg_type == "node_hashrate":
            addr = msg.get("address", "")
            hr = msg.get("hashrate", 0)
            if addr and addr != self.server_address:
                with self.peer_lock:
                    self.peer_hashrates[addr] = {"hashrate": hr, "last_seen": time.time()}
                    for peer_info in self.peer_sockets.values():
                        if peer_info.get("address") == addr:
                            peer_info["hashrate"] = hr
                            peer_info["is_producer"] = hr > 0
                            break
                print(f"[P2P] 收到节点 {addr} 算力: {hr} h/s (出块节点: {hr > 0})", flush=True)

        elif msg_type == "node_online_users":
            remote_users = msg.get("users", [])
            remote_address = msg.get("address", "unknown")
            current_time = time.time()
            current_height = len(self.chain) - 1
            received_valid = 0
            rejected = 0

            with self.lock:
                for user_info in remote_users:
                    if not isinstance(user_info, dict):
                        continue
                    addr = user_info.get("address")
                    if not addr or addr == BURN_ADDRESS:
                        continue

                    if addr == self.server_address:
                        continue

                    proof = user_info.get("online_proof")
                    if not proof or not isinstance(proof, dict):
                        rejected += 1
                        continue
                    proof_timestamp = proof.get("timestamp", 0)
                    proof_signature = proof.get("signature", "")
                    proof_public_key = proof.get("public_key", "")
                    if not verify_public_key_address(proof_public_key, addr):
                        rejected += 1
                        continue
                    if abs(current_time - proof_timestamp) > self.ONLINE_PROOF_VALIDITY:
                        rejected += 1
                        continue
                    proof_message = f"XODE_ONLINE_PROOF:{addr}:{int(proof_timestamp)}"
                    if not verify_signature(proof_public_key, proof_message, proof_signature):
                        rejected += 1
                        continue
                    if self.MIN_REWARD_BALANCE > 0:
                        if self.balances.get(addr, 0) < self.MIN_REWARD_BALANCE:
                            rejected += 1
                            continue

                    source_node = user_info.get("source_node", remote_address)
                    self.all_online_users[addr] = {
                        "address": source_node,
                        "last_seen": current_time,
                        "proof_timestamp": proof_timestamp,
                        "is_producer": user_info.get("hashrate", 0) > 0,
                        "hashrate": user_info.get("hashrate", 0)
                    }
                    self.online_proofs[addr] = proof
                    received_valid += 1

                    remote_first_seen = user_info.get("first_seen_block")
                    local_first_seen = self.address_first_seen_block.get(addr)
                    if addr == self.server_address:
                        if local_first_seen is None:
                            self.address_first_seen_block[addr] = current_height
                            print(f"[P2P] 本节点冷却记录: {addr} 首次出现于区块 #{current_height}", flush=True)
                    else:
                        if remote_first_seen is not None:
                            if local_first_seen is None:
                                self.address_first_seen_block[addr] = remote_first_seen
                                print(f"[P2P] 同步冷却: {addr} 首次出现于 #{remote_first_seen} (来自 {source_node})", flush=True)
                            elif remote_first_seen < local_first_seen:
                                print(f"[P2P] 更新冷却: {addr} #{local_first_seen} -> #{remote_first_seen} (来自 {source_node})", flush=True)
                                self.address_first_seen_block[addr] = remote_first_seen
                        elif local_first_seen is None:
                            self.address_first_seen_block[addr] = current_height
                            print(f"[P2P] 新用户冷却: {addr} 首次出现于 #{current_height}", flush=True)

                    ip_bound = user_info.get("ip_bound")
                    if ip_bound:
                        client_ip = user_info.get("client_ip")
                        if client_ip:
                            existing_binding_ip = None
                            for ip, bind_info in list(self.ip_bindings.items()):
                                if bind_info.get("address") == addr:
                                    existing_binding_ip = ip
                                    break
                            if existing_binding_ip is None:
                                self.ip_bindings[client_ip] = {
                                    "address": addr,
                                    "unbind_time": user_info.get("unbind_time"),
                                    "first_seen": user_info.get("first_seen", current_time)
                                }
                            else:
                                existing = self.ip_bindings[existing_binding_ip]
                                remote_unbind = user_info.get("unbind_time")
                                if remote_unbind is not None:
                                    if existing.get("unbind_time") is None or remote_unbind < existing["unbind_time"]:
                                        existing["unbind_time"] = remote_unbind

            print(f"[P2P] 收到节点 {remote_address} 的全网视图: {received_valid} 个有效, "
                  f"{rejected} 个被拒绝 (无有效证明)", flush=True)
        elif msg_type == "node_tx":
            tx = msg.get("transaction", {})
            if tx:
                required_fields = ["from", "to", "amount", "signature", "public_key", "nonce"]
                if not all(f in tx for f in required_fields):
                    print(f"[P2P] 忽略格式错误的转发交易", flush=True)
                    return
                from_addr = tx.get("from")
                tx_nonce = tx.get("nonce")
                last_nonce = self.address_nonces.get(from_addr, -1)
                if tx_nonce <= last_nonce:
                    print(f"[P2P] 忽略重复/过期交易 nonce={tx_nonce} (last={last_nonce})", flush=True)
                    return
                amount = tx.get("amount")
                if tx.get("amount_atomic") is not None:
                    amount = from_atomic(tx.get("amount_atomic"))
                success, result = self.add_to_mempool(
                    from_addr, tx.get("to"), amount,
                    signature=tx.get("signature"),
                    public_key=tx.get("public_key"),
                    tx_timestamp=tx.get("timestamp"),
                    tx_nonce=tx_nonce,
                    is_forwarded=True
                )
                if success:
                    print(f"[P2P] 交易入池成功: {tx.get('from', '?')} -> {tx.get('to', '?')} {amount} XODE", flush=True)
                    tx_hash = tx.get("tx_hash")
                    if tx_hash and tx_hash not in self.broadcasted_tx_hashes:
                        self.broadcasted_tx_hashes.add(tx_hash)
                        self._broadcast_to_peers({
                            "type": "node_tx",
                            "transaction": tx,
                            "address": self.server_address
                        })
                else:
                    print(f"[P2P] 交易入池失败: {result}", flush=True)

        elif msg_type == "getheaders":
            self._handle_getheaders(sock, msg)

        elif msg_type == "headers":
            self._handle_headers(sock, msg)

        elif msg_type == "inv":
            self._handle_inv(sock, msg)

        elif msg_type == "getdata":
            self._handle_getdata(sock, msg)

        elif msg_type == "block":
            self._handle_block_message(sock, msg)

        elif msg_type == "node_chain_info":
            remote_height = msg.get("block_height", 0)
            remote_address = msg.get("address", "unknown")
            local_height = len(self.chain) - 1

            with self.peer_lock:
                if sock in self.peer_sockets:
                    self.peer_sockets[sock]["block_height"] = remote_height

            should_sync = False
            with self.peer_lock:
                if sock in self.peer_sockets:
                    info = self.peer_sockets[sock]
                    last_sync = info.get("last_sync_time", 0)
                    if (remote_height > local_height and 
                        not self.syncing and 
                        time.time() - last_sync > 60):
                        info["last_sync_time"] = time.time()
                        should_sync = True

            if should_sync:
                print(f"[P2P] 节点 {remote_address} 高度 {remote_height} > 本地 {local_height}，启动一次同步", flush=True)
                self._request_headers_from_peer(sock)
            else:
                if remote_height > local_height:
                    print(f"[P2P] 节点 {remote_address} 高度 {remote_height}，本地 {local_height} (同步冷却中或已在同步)", flush=True)
                else:
                    print(f"[P2P] 节点 {remote_address} 高度 {remote_height}，本地 {local_height}", flush=True)

        elif msg_type == "node_get_blocks":
            try:
                start_idx = msg.get("start", 0)
                end_idx = msg.get("end", len(self.chain))
                if end_idx - start_idx > 100:
                    end_idx = start_idx + 100
                blocks = []
                for i in range(start_idx, min(end_idx, len(self.chain))):
                    b = self.chain[i]
                    blocks.append({
                        "index": b.index,
                        "timestamp": b.timestamp,
                        "previous_hash": b.previous_hash,
                        "hash": b.hash,
                        "nonce": b.nonce,
                        "difficulty": b.difficulty,
                        "reward_tx": b.reward_tx,
                        "transactions": b.transactions
                    })
                response = {
                    "type": "node_blocks",
                    "blocks": blocks,
                    "start": start_idx,
                    "end": start_idx + len(blocks),
                    "total_blocks": len(self.chain)
                }
                try:
                    sock.sendall(encode_message(response))
                except Exception as e:
                    print(f"[P2P] 发送区块响应失败: {e}", flush=True)
            except Exception as e:
                print(f"[P2P] 处理 node_get_blocks 失败: {e}", flush=True)

        elif msg_type == "node_blocks":
            blocks = msg.get("blocks", [])
            for block_data in blocks:
                self._handle_block_message(sock, {"type": "block", "block": block_data})

    def _handle_getheaders(self, sock, msg):
        with self.peer_lock:
            if sock in self.peer_sockets:
                last = self.peer_sockets[sock].get("last_getheaders", 0)
                if time.time() - last < 5:
                    return
                self.peer_sockets[sock]["last_getheaders"] = time.time()

        locator = msg.get("locator", [])
        hashstop = msg.get("hashstop", "0" * 64)

        if not self.chain:
            return

        common_ancestor_idx = -1
        for h in locator:
            for i, block in enumerate(self.chain):
                if block.hash == h:
                    common_ancestor_idx = i
                    break
            if common_ancestor_idx >= 0:
                break

        headers = []
        for i in range(common_ancestor_idx + 1, len(self.chain)):
            block = self.chain[i]
            headers.append({
                "index": block.index,
                "hash": block.hash,
                "previous_hash": block.previous_hash,
                "timestamp": block.timestamp,
                "nonce": block.nonce,
                "difficulty": block.difficulty
            })
            if len(headers) >= MAX_HEADERS_RESULTS:
                break
            if block.hash == hashstop:
                break

        if headers:
            response = {
                "type": "headers",
                "address": self.server_address,
                "headers": headers,
                "count": len(headers)
            }
            try:
                sock.sendall(encode_message(response))
                print(f"[P2P同步] 响应 getheaders，发送 {len(headers)} 个区块头 (从 #{headers[0]['index']})", flush=True)
            except Exception as e:
                print(f"[P2P同步] 发送 headers 失败: {e}", flush=True)

    def _handle_headers(self, sock, msg):
        headers = msg.get("headers", [])
        if not headers:
            with self.sync_lock:
                self.headers_synced = True
                self.syncing = False
            print("[P2P同步] 收到空 headers，标记同步完成", flush=True)
            return

        print(f"[P2P同步] 收到 {len(headers)} 个区块头，开始处理...", flush=True)
        self._process_headers(headers, sock)

        if len(headers) >= MAX_HEADERS_RESULTS:
            self._request_headers_from_peer(sock)

    def _handle_inv(self, sock, msg):
        items = msg.get("items", [])
        if not items:
            return

        getdata_items = []
        for item in items:
            if item.get("type") == "block":
                h = item.get("hash")
                if h and h not in self.block_inventory and h not in self.pending_block_requests:
                    getdata_items.append({"type": "block", "hash": h})

        if getdata_items:
            for i in range(0, len(getdata_items), MAX_BLOCKS_PER_GETDATA):
                batch = getdata_items[i:i + MAX_BLOCKS_PER_GETDATA]
                response = {
                    "type": "getdata",
                    "address": self.server_address,
                    "inventory": batch
                }
                try:
                    sock.sendall(encode_message(response))
                    with self.sync_lock:
                        for item in batch:
                            self.pending_block_requests.add(item["hash"])
                    print(f"[P2P同步] inv 触发请求 {len(batch)} 个区块", flush=True)
                except Exception as e:
                    print(f"[P2P同步] 发送 getdata 失败: {e}", flush=True)

    def _handle_getdata(self, sock, msg):
        inventory = msg.get("inventory", [])
        if not inventory:
            return

        for item in inventory:
            if item.get("type") == "block":
                h = item.get("hash")
                for block in self.chain:
                    if block.hash == h:
                        response = {
                            "type": "block",
                            "address": self.server_address,
                            "block": block.to_dict()
                        }
                        try:
                            sock.sendall(encode_message(response))
                        except Exception as e:
                            print(f"[P2P同步] 发送区块 {h[:16]}... 失败: {e}", flush=True)
                        break

    def _handle_block_message(self, sock, msg):
        block_data = msg.get("block", {})
        if not block_data:
            return

        h = block_data.get("hash")
        with self.sync_lock:
            if h in self.pending_block_requests:
                self.pending_block_requests.discard(h)

        success = self._try_connect_block(block_data)

        if self.syncing and self.sync_peer:
            with self.sync_lock:
                if h in self.sync_block_queue:
                    self.sync_block_queue.remove(h)
                pending_now = len(self.pending_block_requests)
            if pending_now < MAX_BLOCKS_PER_GETDATA:
                self._request_next_sync_batch(self.sync_peer)

        if success:
            inv_msg = {
                "type": "inv",
                "address": self.server_address,
                "items": [{"type": "block", "hash": h, "index": block_data.get("index")}]
            }
            with self.peer_lock:
                for peer_sock in list(self.peer_sockets.keys()):
                    if peer_sock != sock:
                        try:
                            peer_sock.sendall(encode_message(inv_msg))
                        except:
                            pass

            self._print_synced_block(block_data)

        self._process_orphan_blocks()

        with self.sync_lock:
            if self.syncing and len(self.pending_block_requests) == 0 and len(self.orphan_blocks) > 0:
                print(f"[P2P同步] 待下载区块已清空，但孤儿池还有 {len(self.orphan_blocks)} 个，尝试连接...", flush=True)
                self._process_orphan_blocks()

    def _print_synced_block(self, block_data):
        idx = block_data.get("index", 0)
        h = block_data.get("hash", "")
        reward_tx = block_data.get("reward_tx", {})
        online_count = reward_tx.get("online_count", 0)
        ineligible_count = reward_tx.get("ineligible_count", 0)
        block_reward = reward_tx.get("total", 0)
        reward_per_user_atomic = reward_tx.get("reward_per_user_atomic", 0)
        burned_atomic = reward_tx.get("burned_atomic", 0)
        remaining = to_atomic(self.TOTAL_SUPPLY) - self.total_issued
        burned_total = self.get_burned_amount()
        txs = block_data.get("transactions", [])

        print("", flush=True)
        print("=" * 60, flush=True)
        print("[新区块] #" + str(idx), flush=True)
        print("  哈希: " + h, flush=True)
        print("  前一哈希: " + block_data.get("previous_hash", "")[:30] + "...", flush=True)
        print("  时间: " + datetime.fromtimestamp(block_data.get("timestamp", 0)).strftime('%Y-%m-%d %H:%M:%S'), flush=True)
        print("  难度: " + f"{block_data.get('difficulty', 0):.4f}", flush=True)
        print("  Nonce: " + str(block_data.get("nonce", 0)), flush=True)
        print("  有资格分奖: " + str(online_count), flush=True)
        if ineligible_count > 0:
            print("  等待分奖(未满15区块): " + str(ineligible_count), flush=True)
        print("  总奖励: " + format_amount(to_atomic(block_reward)) + " XODE", flush=True)
        producer_reward = block_data.get("reward_tx", {}).get("producer_reward_atomic", 0)
        if producer_reward > 0:
            print("  出块节点奖励(20%): " + format_amount(producer_reward) + " XODE", flush=True)
        producer_reward_atomic = reward_tx.get("producer_reward_atomic", 0)
        producer_eligible = reward_tx.get("producer_eligible", False)
        pool_user_count = online_count - (1 if producer_eligible else 0)
        producer_burned = 0 if producer_eligible else producer_reward_atomic
        pool_burned = burned_atomic - producer_burned
        
        if pool_user_count > 0:
            online_pool_atomic = reward_per_user_atomic * pool_user_count + pool_burned
            print("  在线用户奖励(80%): " + format_amount(online_pool_atomic) + " XODE", flush=True)
            print("  有资格用户: " + str(pool_user_count) + " 人", flush=True)
            print("  每人基础分得: " + format_amount(reward_per_user_atomic) + " XODE", flush=True)
        else:
            print("  在线用户奖励(80%): 0 XODE (无资格用户)", flush=True)
        if txs:
            print("  打包交易: " + str(len(txs)) + " 笔", flush=True)
        print("  已发行: " + format_amount(self.total_issued) + " / " + format_amount(to_atomic(self.TOTAL_SUPPLY)) + " XODE", flush=True)
        print("  剩余: " + format_amount(remaining) + " XODE", flush=True)
        print("  累计销毁: " + format_amount(burned_total) + " XODE", flush=True)
        print("=" * 60, flush=True)

    def _build_mining_template(self, producer_address=None):
        if producer_address is None:
            producer_address = self.server_address

        online_users = self._get_all_online_users_for_reward()

        unique_addresses = set()
        unique_online_users = []
        for user in online_users:
            addr = user["address"]
            if addr not in unique_addresses:
                unique_addresses.add(addr)
                unique_online_users.append(user)

        if producer_address not in unique_addresses and producer_address != BURN_ADDRESS:
            unique_online_users.append({
                "address": producer_address,
                "socket": None,
                "first_seen_block": self.address_first_seen_block.get(producer_address),
                "source": "external_miner"
            })
            unique_addresses.add(producer_address)

        now = time.time()
        current_mtp = self.get_median_time_past()
        block_timestamp = max(int(now), current_mtp + 1)
        new_block_index = len(self.chain)

        eligible_users = []
        ineligible_users = []
        current_height_check = len(self.chain) - 1
        for user in unique_online_users:
            addr = user["address"]
            if addr == BURN_ADDRESS:
                continue
            first_seen = self.address_first_seen_block.get(addr)
            if first_seen is None:
                continue
            blocks_waited = current_height_check - first_seen
            if blocks_waited >= BLOCKS_BEFORE_REWARD:
                eligible_users.append(user)
            else:
                ineligible_users.append(user)

        online_count = len(eligible_users)

        if self.total_issued >= to_atomic(self.TOTAL_SUPPLY):
            return None, "Total supply reached"

        remaining_supply = from_atomic(to_atomic(self.TOTAL_SUPPLY) - self.total_issued)
        block_reward = min(self.BLOCK_REWARD, remaining_supply)
        block_reward_atomic = to_atomic(block_reward)

        is_producer_eligible = producer_address in [u["address"] for u in eligible_users]
        producer_reward_atomic = int(block_reward_atomic * PRODUCER_REWARD_SHARE)
        online_pool_atomic = block_reward_atomic - producer_reward_atomic

        eligible_for_pool = [u for u in eligible_users if u["address"] != producer_address]
        pool_user_count = len(eligible_for_pool)

        if pool_user_count > 0:
            reward_per_user_atomic = online_pool_atomic // pool_user_count
            pool_burned = online_pool_atomic - (reward_per_user_atomic * pool_user_count)
        else:
            reward_per_user_atomic = 0
            pool_burned = online_pool_atomic

        if is_producer_eligible:
            producer_extra_atomic = producer_reward_atomic
            producer_burned = 0
        else:
            producer_extra_atomic = 0
            producer_burned = producer_reward_atomic

        burned = pool_burned + producer_burned
        maturity = new_block_index + REWARD_CONFIRMATIONS

        prebuilt_recipients = []
        if is_producer_eligible:
            prebuilt_recipients.append({
                "address": producer_address,
                "amount": from_atomic(producer_extra_atomic),
                "amount_atomic": producer_extra_atomic,
                "is_producer": True
            })
        for user in eligible_for_pool:
            prebuilt_recipients.append({
                "address": user["address"],
                "amount": from_atomic(reward_per_user_atomic),
                "amount_atomic": reward_per_user_atomic,
                "is_producer": False
            })
        if burned > 0:
            prebuilt_recipients.append({
                "address": BURN_ADDRESS,
                "amount": from_atomic(burned),
                "amount_atomic": burned
            })

        reward_tx = {
            "total": block_reward,
            "online_count": online_count,
            "ineligible_count": len(ineligible_users),
            "producer_node": producer_address,
            "producer_eligible": is_producer_eligible,
            "producer_reward": from_atomic(producer_extra_atomic),
            "producer_reward_atomic": producer_extra_atomic,
            "reward_per_user": from_atomic(reward_per_user_atomic),
            "reward_per_user_atomic": reward_per_user_atomic,
            "burned": from_atomic(burned),
            "burned_atomic": burned,
            "burn_address": BURN_ADDRESS,
            "recipients": prebuilt_recipients
        }

        with self.lock:
            self._clean_expired_txs()
            all_pending_txs = list(self.pending_transactions.values())
            block_transactions = self._select_txs_for_block(all_pending_txs)
            latest = self.get_latest_block()
            difficulty = self.get_difficulty()
            import copy
            block_template = {
                "index": new_block_index,
                "timestamp": block_timestamp,
                "previous_hash": latest.hash,
                "reward_tx": copy.deepcopy(reward_tx),
                "transactions": copy.deepcopy(block_transactions),
                "difficulty": difficulty
            }

        return block_template, None

    def broadcast_block_to_clients(self, block):
        block_data = {
            "type": "new_block",
            "index": block.index,
            "hash": block.hash,
            "previous_hash": block.previous_hash,
            "timestamp": block.timestamp,
            "nonce": block.nonce,
            "difficulty": block.difficulty,
            "reward": block.reward_tx,
            "supply": {
                "issued": self.total_issued,
                "issued_atomic": self.total_issued,
                "total": to_atomic(self.TOTAL_SUPPLY),
                "total_atomic": to_atomic(self.TOTAL_SUPPLY),
                "remaining": to_atomic(self.TOTAL_SUPPLY) - self.total_issued,
                "remaining_atomic": to_atomic(self.TOTAL_SUPPLY) - self.total_issued,
                "burned_total": self.get_burned_amount(),
                "burned_total_atomic": self.get_burned_amount()
            },
            "transactions": block.transactions
        }
        msg_bytes = encode_message(block_data)
        with self.lock:
            dead = []
            for sock in list(self.clients.keys()):
                try:
                    sock.sendall(msg_bytes)
                except:
                    dead.append(sock)
            for sock in dead:
                self.remove_client(sock)

    def _recalc_total_issued_from_chain(self):
        balance_total = sum(bal for addr, bal in self.balances.items() if addr != BURN_ADDRESS)
        burned = self.balances.get(BURN_ADDRESS, 0)
        calculated_issued = balance_total + burned
        if calculated_issued != self.total_issued:
            print(f"[P2P] 修正 total_issued: {format_amount(self.total_issued)} -> {format_amount(calculated_issued)}", flush=True)
            self.total_issued = calculated_issued

    def _sync_chain_from_peers(self):
        print("[P2P同步] 启动同步...", flush=True)

        for _ in range(40):
            with self.peer_lock:
                if self.peer_sockets:
                    has_height = any(
                        info.get("block_height", -1) >= 0
                        for info in self.peer_sockets.values()
                    )
                    if has_height:
                        break
            time.sleep(0.5)
        else:
            print("[P2P同步] 等待节点高度信息超时", flush=True)

        with self.peer_lock:
            peers = list(self.peer_sockets.items())

        if not peers:
            print("[P2P同步] 没有可用的对等节点", flush=True)
            if not self.chain:
                self.create_genesis_block()
            return

        with self.sync_lock:
            self.syncing = True
            self.sync_start_time = time.time()
            self.sync_peer = None

        best_peer = None
        best_height = -1
        for sock, info in peers:
            height = info.get("block_height", -1)
            if height > best_height:
                best_height = height
                best_peer = sock

        local_height = len(self.chain) - 1
        if best_height <= local_height:
            print(f"[P2P同步] 本地高度 {local_height} 已是最新，无需同步", flush=True)
            with self.sync_lock:
                self.syncing = False
            if not self.chain:
                self.create_genesis_block()
            return

        if not best_peer:
            print("[P2P同步] 无法找到合适的同步节点", flush=True)
            with self.sync_lock:
                self.syncing = False
            if not self.chain:
                self.create_genesis_block()
            return

        peer_info = self.peer_sockets.get(best_peer, {})
        print(f"[P2P同步] 从节点 {peer_info.get('host', '?')}:{peer_info.get('port', '?')} 同步，远程高度: {best_height}", flush=True)
        self.sync_peer = best_peer

        batch_size = 50
        last_height = local_height
        stall_time = time.time()
        last_progress_report = time.time()
        re_request_count = 0
        max_re_requests = 10

        for start in range(local_height + 1, best_height + 1, batch_size):
            end = min(start + batch_size, best_height + 1)
            msg = {
                "type": "node_get_blocks",
                "start": start,
                "end": end
            }
            try:
                best_peer.sendall(encode_message(msg))
                print(f"[P2P同步] 请求区块 #{start} ~ #{end - 1}", flush=True)
            except Exception as e:
                print(f"[P2P同步] 请求区块失败: {e}", flush=True)
                break

            waited = 0
            while self.running:
                time.sleep(0.3)
                waited += 1
                current_height = len(self.chain) - 1

                if current_height >= end - 1:
                    break

                if waited > 100:
                    re_request_count += 1
                    if re_request_count > max_re_requests:
                        print(f"[P2P同步] 重试次数超限({max_re_requests})，放弃同步", flush=True)
                        with self.sync_lock:
                            self.syncing = False
                            self.sync_peer = None
                        return
                    print(f"[P2P同步] 区块 #{start}~#{end-1} 下载停滞，第{re_request_count}次重试...", flush=True)
                    try:
                        best_peer.sendall(encode_message(msg))
                    except Exception as e:
                        print(f"[P2P同步] 重试请求失败: {e}", flush=True)
                        break
                    waited = 0
                    stall_time = time.time()

                if time.time() - last_progress_report > 3:
                    progress_pct = min(100, int((current_height / max(best_height, 1)) * 100))
                    print(f"[P2P同步] 进度 {progress_pct}% | 高度 #{current_height}/{best_height}", flush=True)
                    last_progress_report = time.time()

                if time.time() - self.sync_start_time > SYNC_TIMEOUT:
                    print("[P2P同步] 同步超时，标记完成", flush=True)
                    break

            if not self.running:
                break

        current_height = len(self.chain) - 1
        print(f"[P2P同步] 同步结束，本地高度: #{current_height}", flush=True)
        with self.sync_lock:
            self.syncing = False
            self.sync_peer = None
        self._recalc_total_issued_from_chain()
        self.save_data()

    def _broadcast_to_peers(self, msg_dict):
        data = encode_message(msg_dict)
        with self.peer_lock:
            dead = []
            for sock in list(self.peer_sockets.keys()):
                try:
                    sock.sendall(data)
                except:
                    dead.append(sock)
            for sock in dead:
                if sock in self.peer_sockets:
                    del self.peer_sockets[sock]
                try:
                    sock.close()
                except:
                    pass

    def _send_online_users_to_peer(self, sock):
        with self.lock:
            all_users = []
            current_time = time.time()
            local_addrs = set()

            my_first_seen = self.address_first_seen_block.get(self.server_address)
            if my_first_seen is None:
                my_first_seen = len(self.chain) - 1
                self.address_first_seen_block[self.server_address] = my_first_seen
            my_proof = self.online_proofs.get(self.server_address)
            all_users.append({
                "address": self.server_address,
                "first_seen_block": my_first_seen,
                "ip_bound": True,
                "client_ip": "127.0.0.1",
                "unbind_time": None,
                "online_proof": my_proof,
                "source_node": self.server_address
            })
            local_addrs.add(self.server_address)

            for info in self.clients.values():
                addr = info["address"]
                if addr == self.server_address:
                    continue
                local_addrs.add(addr)
                first_seen = self.address_first_seen_block.get(addr)
                client_ip = info["addr"][0]
                ip_info = self.ip_bindings.get(client_ip, {})
                proof = self.online_proofs.get(addr)
                all_users.append({
                    "address": addr,
                    "first_seen_block": first_seen,
                    "ip_bound": True,
                    "client_ip": client_ip,
                    "unbind_time": ip_info.get("unbind_time"),
                    "online_proof": proof,
                    "source_node": self.server_address
                })

            for addr, info in self.all_online_users.items():
                if addr in local_addrs:
                    continue
                first_seen = self.address_first_seen_block.get(addr)
                proof = self.online_proofs.get(addr)
                all_users.append({
                    "address": addr,
                    "first_seen_block": first_seen,
                    "ip_bound": False,
                    "client_ip": None,
                    "unbind_time": None,
                    "online_proof": proof,
                    "source_node": info.get("address", "remote")
                })

        msg = {
            "type": "node_online_users",
            "address": self.server_address,
            "users": all_users,
            "total_count": len(all_users),
            "local_count": len(local_addrs)
        }
        try:
            sock.sendall(encode_message(msg))
            valid_count = sum(1 for u in all_users if u.get("online_proof"))
            remote_count = len(all_users) - len(local_addrs)
            print(f"[P2P] 已向节点发送全网视图: {len(all_users)} 个在线用户 "
                  f"(本地: {len(local_addrs)}, 远程: {remote_count}, 有效证明: {valid_count})", flush=True)
        except Exception as e:
            print(f"[P2P] 发送在线用户失败: {e}", flush=True)
    def _sync_online_users_loop(self):
        while self.running:
            time.sleep(30)
            if not self.running:
                break

            with self.lock:
                all_users = []
                current_time = time.time()
                local_addrs = set()

                my_proof = self.online_proofs.get(self.server_address)
                if not my_proof or abs(current_time - my_proof["timestamp"]) > self.ONLINE_PROOF_VALIDITY * 0.7:
                    ts = int(current_time)
                    msg = f"XODE_ONLINE_PROOF:{self.server_address}:{ts}"
                    sig = self.wallet.sign(msg)
                    self.online_proofs[self.server_address] = {
                        "signature": sig,
                        "timestamp": ts,
                        "public_key": self.server_public_key
                    }
                    my_proof = self.online_proofs[self.server_address]

                my_first_seen = self.address_first_seen_block.get(self.server_address)
                if my_first_seen is None:
                    my_first_seen = len(self.chain) - 1
                    self.address_first_seen_block[self.server_address] = my_first_seen
                all_users.append({
                    "address": self.server_address,
                    "first_seen_block": my_first_seen,
                    "ip_bound": True,
                    "client_ip": "127.0.0.1",
                    "unbind_time": None,
                    "online_proof": my_proof,
                    "source_node": self.server_address,
                    "is_producer": self.local_hashrate > 0,
                    "hashrate": self.local_hashrate
                })
                local_addrs.add(self.server_address)

                for info in self.clients.values():
                    addr = info["address"]
                    if addr == self.server_address:
                        continue
                    local_addrs.add(addr)
                    first_seen = self.address_first_seen_block.get(addr)
                    client_ip = info["addr"][0]
                    ip_info = self.ip_bindings.get(client_ip, {})
                    proof = self.online_proofs.get(addr)
                    all_users.append({
                        "address": addr,
                        "first_seen_block": first_seen,
                        "ip_bound": True,
                        "client_ip": client_ip,
                        "unbind_time": ip_info.get("unbind_time"),
                        "online_proof": proof,
                        "source_node": self.server_address,
                        "is_producer": False,
                        "hashrate": 0
                    })

                for addr, info in self.all_online_users.items():
                    if addr in local_addrs:
                        continue
                    first_seen = self.address_first_seen_block.get(addr)
                    proof = self.online_proofs.get(addr)
                    all_users.append({
                        "address": addr,
                        "first_seen_block": first_seen,
                        "ip_bound": False,
                        "client_ip": None,
                        "unbind_time": None,
                        "online_proof": proof,
                        "source_node": info.get("address", "remote"),
                        "is_producer": info.get("is_producer", False),
                        "hashrate": info.get("hashrate", 0)
                    })

            msg = {
                "type": "node_online_users",
                "address": self.server_address,
                "users": all_users,
                "total_count": len(all_users),
                "local_count": len(local_addrs)
            }
            valid_proof_count = sum(1 for u in all_users if u.get("online_proof"))
            remote_count = len(all_users) - len(local_addrs)
            print(f"[P2P] 广播全网视图: {len(all_users)} 个在线用户 "
                  f"(本地: {len(local_addrs)}, 远程: {remote_count}, 有效证明: {valid_proof_count})", flush=True)
            self._broadcast_to_peers(msg)

            current_time = time.time()
            with self.lock:
                expired = []
                for addr, info in list(self.all_online_users.items()):
                    last_seen = info.get("last_seen", 0)
                    if current_time - last_seen > BIND_TIMEOUT:
                        expired.append(addr)
                for addr in expired:
                    del self.all_online_users[addr]
                    print(f"[在线过期] 地址 {addr} 超过1小时未在其他节点报告在线，从全局移除", flush=True)

                expired_proofs = [
                    addr for addr, proof in list(self.online_proofs.items())
                    if current_time - proof.get("timestamp", 0) > self.ONLINE_PROOF_VALIDITY
                ]
                for addr in expired_proofs:
                    del self.online_proofs[addr]
                    if addr in self.all_online_users:
                        del self.all_online_users[addr]
                if expired_proofs:
                    print(f"[在线证明] 清理 {len(expired_proofs)} 个过期证明", flush=True)
    def _peer_reconnect_loop(self):
        while self.running:
            time.sleep(self._peer_reconnect_interval)
            if not self.running:
                break
            with self.peer_lock:
                connected_hosts = {(info["host"], info["port"]) for info in self.peer_sockets.values()}
            for host, port in self.peer_addrs:
                if (host, port) not in connected_hosts:
                    print(f"[P2P] 尝试重连节点 {host}:{port}", flush=True)
                    self._connect_to_peer(host, port)

    def _peer_exchange_loop(self):
        while self.running:
            time.sleep(600)
            if not self.running:
                break

            with self.peer_lock:
                if not self.peer_sockets:
                    continue
                peers_list = []
                for addr_str, info in self.known_peers.items():
                    if not info.get("is_public", False):
                        continue
                    if ":" in addr_str:
                        host, port = addr_str.rsplit(":", 1)
                        peers_list.append({
                            "host": host,
                            "port": int(port),
                            "address": info.get("address"),
                            "is_producer": info.get("is_producer", False),
                            "is_public": True
                        })

            if peers_list:
                msg = {
                    "type": "node_peers",
                    "address": self.server_address,
                    "peers": peers_list
                }
                self._broadcast_to_peers(msg)
                print(f"[P2P] 定期交换peers，向 {len(self.peer_sockets)} 个节点广播 {len(peers_list)} 个已知节点", flush=True)

    def _peer_heartbeat_loop(self):
        while self.running:
            time.sleep(self._peer_heartbeat_interval)
            if not self.running:
                break
            msg = {"type": "node_ping", "address": self.server_address, "timestamp": time.time()}
            self._broadcast_to_peers(msg)

            hashrate_msg = {
                "type": "node_hashrate",
                "address": self.server_address,
                "hashrate": self.local_hashrate
            }
            self._broadcast_to_peers(hashrate_msg)

            with self.peer_lock:
                peers = list(self.peer_sockets.items())
            local_height = len(self.chain) - 1
            for sock, info in peers:
                remote_height = info.get("block_height", -1)
                if remote_height > local_height:
                    print(f"[P2P同步] 心跳检测到节点 {info.get('host')}:{info.get('port')} 高度 {remote_height} > 本地 {local_height}，主动同步", flush=True)
                    self._request_headers_from_peer(sock)

            current_time = time.time()
            with self.peer_lock:
                dead = []
                for sock, info in list(self.peer_sockets.items()):
                    if current_time - info.get("last_pong", 0) > 90 and info.get("last_pong", 0) > 0:
                        host = info.get("host")
                        port = info.get("port")
                        print(f"[P2P] 节点 {host}:{port} 心跳超时", flush=True)
                        dead.append(sock)
                        self._mark_peer_failed(host, port, reason="心跳超时")
                for sock in dead:
                    del self.peer_sockets[sock]
                    try:
                        sock.close()
                    except:
                        pass

            current_time = time.time()
            expired_hashrate = []
            with self.peer_lock:
                for addr, info in list(self.peer_hashrates.items()):
                    if current_time - info.get("last_seen", 0) > 300:
                        expired_hashrate.append(addr)
                for addr in expired_hashrate:
                    del self.peer_hashrates[addr]
                if expired_hashrate:
                    print(f"[P2P] 清理 {len(expired_hashrate)} 个过期算力记录", flush=True)

    def _get_all_online_users_for_reward(self):
        with self.lock:
            global_users = []
            seen_addrs = set()
            current_time = time.time()
            local_count = 0
            remote_count = 0

            for sock, info in self.clients.items():
                addr = info["address"]
                if addr not in seen_addrs and addr != BURN_ADDRESS:
                    proof = self.online_proofs.get(addr)
                    if proof and abs(current_time - proof["timestamp"]) <= self.ONLINE_PROOF_VALIDITY:
                        seen_addrs.add(addr)
                        first_seen = self.address_first_seen_block.get(addr)
                        global_users.append({
                            "address": addr,
                            "socket": sock,
                            "first_seen_block": first_seen,
                            "source": "local"
                        })
                        local_count += 1

            for addr, info in self.all_online_users.items():
                if addr not in seen_addrs and addr != BURN_ADDRESS:
                    last_seen = info.get("last_seen", 0)
                    if current_time - last_seen <= BIND_TIMEOUT:
                        proof = self.online_proofs.get(addr)
                        if proof and abs(current_time - proof["timestamp"]) <= self.ONLINE_PROOF_VALIDITY:
                            seen_addrs.add(addr)
                            first_seen = self.address_first_seen_block.get(addr)
                            global_users.append({
                                "address": addr,
                                "socket": None,
                                "first_seen_block": first_seen,
                                "source": info.get("address", "remote")
                            })
                            remote_count += 1

            if self.server_address not in seen_addrs and self.server_address != BURN_ADDRESS:
                my_proof = self.online_proofs.get(self.server_address)
                if not my_proof or abs(current_time - my_proof["timestamp"]) > self.ONLINE_PROOF_VALIDITY:
                    ts = int(current_time)
                    msg = f"XODE_ONLINE_PROOF:{self.server_address}:{ts}"
                    sig = self.wallet.sign(msg)
                    self.online_proofs[self.server_address] = {
                        "signature": sig,
                        "timestamp": ts,
                        "public_key": self.server_public_key
                    }
                first_seen = self.address_first_seen_block.get(self.server_address)
                if first_seen is None:
                    first_seen = len(self.chain) - 1
                    self.address_first_seen_block[self.server_address] = first_seen
                seen_addrs.add(self.server_address)
                global_users.append({
                    "address": self.server_address,
                    "socket": None,
                    "first_seen_block": first_seen,
                    "source": "self"
                })

            total = len(global_users)
            if total > 0:
                print(f"[全局视图] 总在线: {total} (本地: {local_count}, 远程: {remote_count}, 本节点: 1)", flush=True)
            return global_users

    def block_production_loop(self):
        print("出块模式", flush=True)

        if not self.is_producer:
            print("同步模式", flush=True)
            return

        wait_start = time.time()
        while self.running and not self.chain:
            if time.time() - wait_start > 60:
                print("[出块] 等待链同步超时，将作为单节点创建创世区块", flush=True)
                with self.chain_lock:
                    if not self.chain:
                        self.create_genesis_block()
                break
            print("[出块] 等待链同步就绪...", flush=True)
            time.sleep(2)

        if not self.chain:
            print("[出块] 链仍为空，无法启动挖矿", flush=True)
            return

        print(f"[出块] 链已就绪，当前高度 #{len(self.chain)-1}，开始挖矿竞争", flush=True)

        if self.is_producer:
            warmup_start = time.time()
            while self.running:
                time_elapsed = time.time() - warmup_start
                local_height = len(self.chain) - 1

                with self.peer_lock:
                    max_peer_height = max(
                        (info.get("block_height", -1) for info in self.peer_sockets.values()),
                        default=-1
                    )
                    connected_producers = sum(
                        1 for info in self.peer_sockets.values()
                        if info.get("hashrate", 0) > 0 and info.get("connected")
                    )

                is_synced = local_height >= max_peer_height
                has_peer_producers = connected_producers > 0
                no_higher_peers = max_peer_height < 0

                if time_elapsed >= 60 and is_synced and (has_peer_producers or no_higher_peers):
                    print(f"[出块] 启动预热完成，时间:{time_elapsed:.0f}s "
                          f"高度:{local_height} 连接生产者:{connected_producers}，开始挖矿", flush=True)
                    break

                print(f"[出块] 启动预热中... 时间:{time_elapsed:.0f}s "
                      f"高度:{local_height}/{max(max_peer_height, local_height)} "
                      f"生产者连接:{connected_producers}，暂不挖矿", flush=True)
                time.sleep(5)

        while self.running:
            if not self.running:
                break
            if self.total_issued >= to_atomic(self.TOTAL_SUPPLY):
                print("[出块] 总量已达上限，停止出块", flush=True)
                break

            result = self.produce_block()
            if result is None:
                time.sleep(0.1)
                continue

            time.sleep(0.1)

        print("[出块] 出块循环已停止", flush=True)

    def mempool_cleanup_loop(self):
        while self.running:
            time.sleep(600)
            if not self.running:
                break
            with self.lock:
                count = self._clean_expired_txs()
                if len(self.broadcasted_tx_hashes) > 100000:
                    self.broadcasted_tx_hashes.clear()
                    print(f'[Mempool] 清理 broadcasted_tx_hashes 集合', flush=True)
                if len(self.block_inventory) > 500000:
                    recent_hashes = set()
                    for b in self.chain[-10000:]:
                        recent_hashes.add(b.hash)
                        recent_hashes.add(b.previous_hash)
                    self.block_inventory = recent_hashes
                    print(f'[Mempool] 清理 block_inventory 集合，保留最近 10000 区块', flush=True)
            if count > 0:
                self.save_data()



    def scan_address_history(self):
        my_addr = self.wallet.address
        if not my_addr:
            return

        history = []
        current_height = len(self.chain) - 1

        for block in self.chain:
            idx = block.index
            ts = block.timestamp

            # Check reward_tx recipients
            reward_tx = block.reward_tx or {}
            for r in reward_tx.get("recipients", []):
                addr = r.get("address")
                amt_atomic = r.get("amount_atomic")
                if amt_atomic is None:
                    amt_atomic = to_atomic(r.get("amount", 0))
                if addr == my_addr and amt_atomic > 0:
                    is_producer = r.get("is_producer", False)
                    history.append({
                        "type": "reward",
                        "from": "SYSTEM",
                        "to": my_addr,
                        "amount": from_atomic(amt_atomic),
                        "amount_atomic": amt_atomic,
                        "fee": 0,
                        "fee_atomic": 0,
                        "timestamp": ts,
                        "block_index": idx,
                        "status": "confirmed",
                        "tx_hash": block.hash + "_reward",
                        "is_producer_reward": is_producer,
                        "reward_source": "block_production",
                        "maturity_block": idx + REWARD_CONFIRMATIONS
                    })

            # Check transactions
            for tx in block.transactions:
                tx_from = tx.get("from")
                tx_to = tx.get("to")
                if tx_from == my_addr or tx_to == my_addr:
                    tx_copy = dict(tx)
                    tx_copy["block_index"] = idx
                    tx_copy["status"] = "confirmed"
                    if tx_from == my_addr:
                        tx_copy["direction"] = "out"
                    else:
                        tx_copy["direction"] = "in"
                    history.append(tx_copy)

        # Sort by block_index ascending
        history.sort(key=lambda x: (x.get("block_index", 0), x.get("timestamp", 0)))
        self.address_history = history
        self.save_address_history()
        return history

    def save_address_history(self):
        """Save address history to JSON file."""
        try:
            data = {
                "address": self.wallet.address,
                "history": self.address_history,
                "saved_at": time.time(),
                "chain_height": len(self.chain) - 1
            }
            temp = HISTORY_FILE + ".tmp"
            with open(temp, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            if os.path.exists(HISTORY_FILE):
                os.replace(temp, HISTORY_FILE)
            else:
                os.rename(temp, HISTORY_FILE)
        except Exception as e:
            print(f"[History] Save failed: {e}", flush=True)

    def load_address_history(self):
        """Load address history from JSON file."""
        if not os.path.exists(HISTORY_FILE):
            return
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if data.get("address") == self.wallet.address:
                self.address_history = data.get("history", [])
                print(f"[History] Loaded {len(self.address_history)} records", flush=True)
            else:
                print("[History] Address mismatch, will rescan", flush=True)
                self.address_history = []
        except Exception as e:
            print(f"[History] Load failed: {e}", flush=True)
            self.address_history = []

    def get_address_stats(self):
        """Calculate statistics from address history."""
        my_addr = self.wallet.address
        total_reward = 0
        total_sent = 0
        total_received = 0
        reward_count = 0
        sent_count = 0
        received_count = 0

        current_height = len(self.chain) - 1
        pending_rewards = 0
        pending_transfers_in = 0

        for tx in self.address_history:
            tx_type = tx.get("type", "transfer")
            direction = tx.get("direction", "")
            amt_atomic = tx.get("amount_atomic", 0)
            if amt_atomic is None:
                amt_atomic = to_atomic(tx.get("amount", 0))

            block_idx = tx.get("block_index")

            if tx_type == "reward":
                total_reward += amt_atomic
                reward_count += 1
                if block_idx is not None and current_height < block_idx + REWARD_CONFIRMATIONS:
                    pending_rewards += 1
            elif direction == "out":
                fee_atomic = tx.get("fee_atomic", 0) or 0
                total_sent += amt_atomic + fee_atomic
                sent_count += 1
            elif direction == "in":
                total_received += amt_atomic
                received_count += 1
                if block_idx is not None and current_height < block_idx + TX_CONFIRMATIONS:
                    pending_transfers_in += 1

        return {
            "total_reward": from_atomic(total_reward),
            "total_reward_atomic": total_reward,
            "total_sent": from_atomic(total_sent),
            "total_sent_atomic": total_sent,
            "total_received": from_atomic(total_received),
            "total_received_atomic": total_received,
            "reward_count": reward_count,
            "sent_count": sent_count,
            "received_count": received_count,
            "pending_rewards": pending_rewards,
            "pending_transfers_in": pending_transfers_in,
            "total_tx_count": len(self.address_history)
        }

    def get_state(self):
        latest = self.chain[-1] if self.chain else None
        my_addr = self.wallet.address
        current_height = len(self.chain) - 1
        first_seen = self.address_first_seen_block.get(my_addr, 0)
        blocks_waited = current_height - first_seen
        cooldown_remaining = max(0, BLOCKS_BEFORE_REWARD - blocks_waited)
        is_eligible = blocks_waited >= BLOCKS_BEFORE_REWARD
        total_bal = self.balances.get(my_addr, 0)
        spendable = self.get_spendable_balance(my_addr)
        locked = total_bal - spendable
        if locked < 0:
            locked = 0
            spendable = total_bal
        elif spendable < 0:
            spendable = 0
            locked = total_bal
        elif (spendable + locked) != total_bal:
            spendable = total_bal - locked
            if spendable < 0:
                spendable = 0
                locked = total_bal

        # Calculate cooldown time estimate
        cooldown_seconds = cooldown_remaining * self.BLOCK_TIME if cooldown_remaining > 0 else 0
        cooldown_minutes = cooldown_seconds // 60
        cooldown_hours = cooldown_minutes // 60

        stats = self.get_address_stats()

        # Calculate average block time from last 10 blocks
        avg_block_time = float(self.BLOCK_TIME)
        if len(self.chain) > 1:
            recent = self.chain[-11:] if len(self.chain) >= 11 else self.chain
            if len(recent) >= 2:
                total_time = recent[-1].timestamp - recent[0].timestamp
                intervals = len(recent) - 1
                if intervals > 0:
                    avg_block_time = total_time / intervals

        # Global online users count
        global_online = len(self._get_all_online_users_for_reward())

        # POW / Producer node count (global view via all_online_users)
        producer_count = 1 if self.is_producer else 0
        with self.lock:
            current_time = time.time()
            for addr, info in self.all_online_users.items():
                if addr != self.server_address and info.get("hashrate", 0) > 0:
                    if current_time - info.get("last_seen", 0) <= self.ONLINE_PROOF_VALIDITY:
                        producer_count += 1

        # Hashrate calculation
        total_network_hashrate = self.local_hashrate
        with self.lock:
            current_time = time.time()
            for addr, info in self.all_online_users.items():
                if addr != self.server_address:
                    hr = info.get("hashrate", 0)
                    if current_time - info.get("last_seen", 0) <= 300:
                        total_network_hashrate += hr
        self.network_hashrate = total_network_hashrate
        hashrate_ratio = (self.local_hashrate / total_network_hashrate * 100) if total_network_hashrate > 0 else 0

        return {
            "connected": True,
            "connected_nodes": len(self.peer_sockets),
            "difficulty": self.chain[-1].difficulty if self.chain else self.INITIAL_DIFFICULTY,
            "balance": from_atomic(total_bal),
            "available_balance": from_atomic(spendable),
            "locked_balance": from_atomic(locked),
            "block_height": current_height,
            "local_height": current_height,
            "online_users": len(self.clients),
            "global_online": global_online,
            "producer_count": producer_count,
            "avg_block_time": round(avg_block_time, 1),
            "total_issued": from_atomic(self.total_issued),
            "total_supply": self.TOTAL_SUPPLY,
            "burned_total": from_atomic(self.get_burned_amount()),
            "address": my_addr,
            "public_key": self.wallet.public_key,
            "block_time": self.BLOCK_TIME,
            "block_reward": self.BLOCK_REWARD,
            "transfer_fee": self.TRANSFER_FEE,
            "pending_tx": len(self.pending_transactions),
            "wallet_file": WALLET_FILE,
            "wallet_created": self.wallet.created_at,
            "nonce": self.address_nonces.get(my_addr, -1),
            "chain": [b.to_dict() for b in self.chain],
            "transaction_history": self.transaction_history.get(my_addr, [])[-50:],
            "address_history": self.address_history[-200:],
            "address_stats": stats,
            "logs": self.logs[-100:],
            "syncing": getattr(self, 'syncing', False),
            "sync_progress": 100,
            "is_eligible": is_eligible,
            "cooldown_remaining": cooldown_remaining,
            "cooldown_seconds": cooldown_seconds,
            "cooldown_minutes": cooldown_minutes,
            "cooldown_hours": cooldown_hours,
            "first_connect_block": first_seen,
            "blocks_waited": blocks_waited,
            "pending_rewards": len(self.pending_rewards.get(my_addr, [])),
            "pending_transfers": len(self.pending_transfers.get(my_addr, [])),
            "local_hashrate": self.local_hashrate,
            "network_hashrate": self.network_hashrate,
            "hashrate_ratio": round(hashrate_ratio, 2),
        }

    def get_rankings(self, limit=100):
        """Return address balance rankings."""
        valid_balances = {
            addr: bal for addr, bal in self.balances.items()
            if addr != BURN_ADDRESS and bal > 0
        }
        sorted_items = sorted(valid_balances.items(), key=lambda x: x[1], reverse=True)[:limit]
        my_addr = self.wallet.address
        my_rank = 0
        my_balance = self.balances.get(my_addr, 0)
        rankings = []
        for i, (addr, bal) in enumerate(sorted_items):
            rank = i + 1
            if addr == my_addr:
                my_rank = rank
            rankings.append({"rank": rank, "address": addr, "balance": from_atomic(bal), "is_me": addr == my_addr})
        return {"rankings": rankings, "total": len(valid_balances), "my_address": my_addr, "my_balance": from_atomic(my_balance), "my_rank": my_rank}

    def search_chain(self, query):
        """Search blockchain for matching blocks or transactions."""
        results = []
        if not query:
            return results
        query_lower = query.lower().strip()
        try:
            idx = int(query_lower)
            if 0 <= idx < len(self.chain):
                results.append(self.chain[idx].to_dict())
                return results
        except ValueError:
            pass
        for block in self.chain:
            block_dict = block.to_dict()
            if query_lower in block.hash.lower() or query_lower in block.previous_hash.lower():
                results.append(block_dict)
                continue
            for tx in block.transactions:
                tx_str = json.dumps(tx, sort_keys=True, ensure_ascii=False).lower()
                if query_lower in tx_str:
                    results.append(block_dict)
                    break
        return results

    def node_transfer(self, to_addr, amount):
        """Create and broadcast a transfer using the node wallet."""
        from_addr = self.wallet.address
        if not self.is_valid_xode_address(to_addr):
            return False, "Invalid target address"
        if from_addr == to_addr:
            return False, "Cannot transfer to self"
        try:
            atomic_amount = to_atomic(amount)
            if atomic_amount <= 0:
                return False, "Amount must be greater than 0"
        except:
            return False, "Invalid amount"
        tx_nonce = self.address_nonces.get(from_addr, -1) + 1
        tx_timestamp = time.time()
        message = build_sign_message(from_addr, to_addr, amount, tx_nonce, tx_timestamp)
        signature = sign_message(self.wallet.private_key, message)
        success, result = self.add_to_mempool(from_addr, to_addr, amount, signature=signature, public_key=self.wallet.public_key, tx_timestamp=tx_timestamp, tx_nonce=tx_nonce)
        if success:
            tx_broadcast = {
                "type": "node_tx",
                "transaction": {
                    "type": "transfer",
                    "from": from_addr,
                    "to": to_addr,
                    "amount": result["amount"],
                    "amount_atomic": result["amount_atomic"],
                    "fee": result["fee"],
                    "fee_atomic": result["fee_atomic"],
                    "signature": signature,
                    "public_key": self.wallet.public_key,
                    "timestamp": tx_timestamp,
                    "nonce": tx_nonce,
                    "tx_hash": result["tx_hash"]
                },
                "address": self.server_address
            }
            if result["tx_hash"] not in self.broadcasted_tx_hashes:
                self.broadcasted_tx_hashes.add(result["tx_hash"])
                self._broadcast_to_peers(tx_broadcast)

            self.transfer_result = {"success": True, "amount": result["amount"], "to": to_addr, "fee": self.TRANSFER_FEE, "balance": from_atomic(self.balances.get(from_addr, 0)), "tx_hash": result["tx_hash"]}
            self.logs.append({"time": datetime.fromtimestamp(time.time()).strftime('%H:%M:%S'), "msg": f"Transfer sent: {from_addr} -> {to_addr} {result['amount']} XODE", "level": "success"})
            return True, f"Transfer sent: {result['amount']} XODE to {to_addr} (tx_hash: {result['tx_hash']})"
        else:
            self.transfer_result = {"success": False, "error": result}
            self.logs.append({"time": datetime.fromtimestamp(time.time()).strftime('%H:%M:%S'), "msg": f"Transfer failed: {result}", "level": "error"})
            return False, result

    def disconnect_all_peers(self):
        """Disconnect all peer connections."""
        with self.peer_lock:
            for sock in list(self.peer_sockets.keys()):
                try:
                    sock.close()
                except:
                    pass
            self.peer_sockets.clear()
        self.logs.append({"time": datetime.fromtimestamp(time.time()).strftime('%H:%M:%S'), "msg": "Disconnected from all peers", "level": "info"})
        return True

    def start_explorer(self, port=7788):
        if not self.running:
            return
        try:
            self.explorer_server = ReuseAddrServer(('0.0.0.0', port), APIHandler)
            self.explorer_server.xode_node = self
            self.explorer_thread = threading.Thread(target=self.explorer_server.serve_forever, daemon=True)
            self.explorer_thread.start()
            print("=" * 60, flush=True)
            print("Web已启动", flush=True)
            print("访问地址: http://127.0.0.1:" + str(port), flush=True)
            print("局域网地址: http://0.0.0.0:" + str(port), flush=True)
            print("=" * 60, flush=True)
        except Exception as e:
            print("[浏览器] 启动失败: " + str(e), flush=True)
    def stop_explorer(self):
        if hasattr(self, 'explorer_server') and self.explorer_server:
            try:
                self.explorer_server.shutdown()
                print("[浏览器] 服务已停止", flush=True)
            except Exception as e:
                print("[浏览器] 停止错误: " + str(e), flush=True)
    def start(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)

            print("=" * 60, flush=True)
            print("XODE 区块链节点服务器", flush=True)

            explorer_port = getattr(self, 'explorer_port', 0)
            if explorer_port > 0:
                self.start_explorer(port=explorer_port)
            print("=" * 60, flush=True)
            print("节点地址: " + self.server_address, flush=True)
            print("节点地址: " + self.server_address, flush=True)
            print("节点角色: " + ("挖矿节点" if self.is_producer else "同步节点"), flush=True)
            print("监听地址: " + self.host + ":" + str(self.port), flush=True)
            print("初始难度: " + str(self.INITIAL_DIFFICULTY), flush=True)
            print("难度调整间隔: " + str(self.DIFFICULTY_ADJUSTMENT_INTERVAL) + " 个区块", flush=True)
            print("出块时间目标: " + str(self.BLOCK_TIME) + " 秒 (" + str(self.BLOCK_TIME // 60) + "分钟)", flush=True)
            print("区块奖励: " + format_amount(to_atomic(self.BLOCK_REWARD)) + " XODE", flush=True)
            print("转账手续费: " + format_amount(to_atomic(self.TRANSFER_FEE)) + " XODE", flush=True)
            print("总量上限: " + format_amount(to_atomic(self.TOTAL_SUPPLY)) + " XODE", flush=True)
            print("销毁地址: " + BURN_ADDRESS, flush=True)
            print("IP绑定保留: " + str(BIND_TIMEOUT) + " 秒 (1小时)", flush=True)
            print("延迟分奖: " + str(BLOCKS_BEFORE_REWARD) + " 区块 (" + str(BLOCKS_BEFORE_REWARD * BLOCK_TIME // 60) + " 分钟)", flush=True)
            print("当前区块: " + str(len(self.chain)), flush=True)
            print("已发行: " + format_amount(self.total_issued) + " XODE", flush=True)
            if self.chain:
                print("当前难度: " + f"{self.chain[-1].difficulty:.4f}", flush=True)
                print("累计销毁: " + format_amount(self.get_burned_amount()) + " XODE", flush=True)
                print("创世区块: " + self.chain[0].hash, flush=True)
            seed_nodes = [p for p in self.peer_addrs if p not in [(info.get("host"), info.get("port")) for info in self.known_peers.values()]]
            if self.peer_addrs:
                print("连接队列: " + str(len(self.peer_addrs)) + " 个节点", flush=True)
                if seed_nodes:
                    print("  种子节点: " + str(seed_nodes), flush=True)
            print("=" * 60, flush=True)

            all_peers = list(self.peer_addrs)
            for addr_str in self.known_peers:
                if ":" in addr_str:
                    host, port = addr_str.rsplit(":", 1)
                    addr_tuple = (host, int(port))
                    if addr_tuple not in all_peers:
                        all_peers.append(addr_tuple)

            if all_peers:
                seed_count = len(self.peer_addrs)
                cached_count = len(all_peers) - seed_count
                print(f"[P2P] 准备连接 {len(all_peers)} 个对等节点 (种子: {seed_count}, 缓存: {cached_count})", flush=True)
                for host, port in all_peers:
                    public_host = self._get_public_host()
                    is_self = False
                    if host in ('127.0.0.1', 'localhost', '0.0.0.0', self.host) and port == self.port:
                        is_self = True
                    if host == public_host and port == self.port:
                        is_self = True
                    if is_self:
                        print(f"[P2P] 跳过自连接目标: {host}:{port}", flush=True)
                        continue
                    self._connect_to_peer(host, port)

                self._sync_chain_from_peers()

                peer_reconnect_thread = threading.Thread(target=self._peer_reconnect_loop, daemon=True)
                peer_reconnect_thread.start()

                peer_heartbeat_thread = threading.Thread(target=self._peer_heartbeat_loop, daemon=True)
                peer_heartbeat_thread.start()

                sync_online_thread = threading.Thread(target=self._sync_online_users_loop, daemon=True)
                sync_online_thread.start()

                peer_exchange_thread = threading.Thread(target=self._peer_exchange_loop, daemon=True)
                peer_exchange_thread.start()
                print("[P2P] Peers定期交换线程已启动 (每10分钟)", flush=True)

            heartbeat_thread = threading.Thread(target=self.heartbeat_checker, daemon=True)
            heartbeat_thread.start()

            block_thread = threading.Thread(target=self.block_production_loop, daemon=True)
            block_thread.start()
            print("出块模式", flush=True)

            mempool_cleanup_thread = threading.Thread(target=self.mempool_cleanup_loop, daemon=True)
            mempool_cleanup_thread.start()
            print('[Mempool] 过期交易清理线程已启动', flush=True)

            while self.running:
                try:
                    self.server_socket.settimeout(1)
                    client_socket, addr = self.server_socket.accept()
                    self.server_socket.settimeout(None)

                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr),
                        daemon=True
                    )
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    print("[错误] 接受连接: " + str(e), flush=True)

        except KeyboardInterrupt:
            print("[关闭] 服务器正在关闭...", flush=True)
        except Exception as e:
            print("[错误] 服务器: " + str(e), flush=True)
        finally:
            self.running = False
            with self.lock:
                for sock in list(self.clients.keys()):
                    try:
                        sock.close()
                    except:
                        pass
            with self.peer_lock:
                for sock in list(self.peer_sockets.keys()):
                    try:
                        sock.close()
                    except:
                        pass
            self.server_socket.close()
            print("服务器已关闭", flush=True)
            print("", flush=True)
            print("最终统计:", flush=True)
            print("  总区块数: " + str(len(self.chain)), flush=True)
            print("  已发行: " + format_amount(self.total_issued) + " / " + format_amount(to_atomic(self.TOTAL_SUPPLY)) + " XODE", flush=True)
            print("  累计销毁: " + format_amount(self.get_burned_amount()) + " XODE", flush=True)
            print("  剩余: " + format_amount(to_atomic(self.TOTAL_SUPPLY) - self.total_issued) + " XODE", flush=True)


if __name__ == "__main__":
    import argparse
    import sys

    if len(sys.argv) == 1:
        print("=" * 60, flush=True)
        print("=" * 60, flush=True)
        print("请选择节点运行模式:", flush=True)
        print("", flush=True)
        print("  [1] 出块节点 (Producer)", flush=True)
        print("      参与 POW", flush=True)
        print("", flush=True)
        print("  [2] 同步节点 (Sync)", flush=True)
        print("      仅同步区块链数据", flush=True)
        print("=" * 60, flush=True)
        
        while True:
            try:
                choice = input("请输入选项 (1 或 2): ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[退出] 用户取消启动", flush=True)
                sys.exit(0)
            
            if choice == "1":
                sys.argv.append("--producer")
                print("[启动] 已选择: 出块节点", flush=True)
                break
            elif choice == "2":
                print("[启动] 已选择: 同步节点", flush=True)
                break
            else:
                print("[提示] 无效输入，请输入 1 或 2", flush=True)
        
        print("=" * 60, flush=True)
        print("", flush=True)

    parser = argparse.ArgumentParser(description="XODE P2P Node Server")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址 (默认: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5566, help="监听端口 (默认: 5566)")
    parser.add_argument("--producer", action="store_true", help="启用挖矿（参与POW竞争）")
    parser.add_argument("--peers", nargs="*", help="其他节点地址，格式: host:port")
    parser.add_argument("--announce-ip", default=None, help="手动指定本节点对外宣告的公网 IP（用于写入 peers.txt 和节点发现）")
    parser.add_argument("--explorer-port", type=int, default=7788, help="区块浏览器端口(0=禁用)")
    args = parser.parse_args()

    peer_addrs = []
    if args.peers:
        for peer in args.peers:
            if ":" in peer:
                host, port = peer.rsplit(":", 1)
                peer_addrs.append((host, int(port)))
            else:
                peer_addrs.append((peer, 5566))

    node = XodeNode(
        host=args.host,
        port=args.port,
        is_producer=args.producer,
        peer_addrs=peer_addrs,
        announce_ip=args.announce_ip
    )
    node.explorer_port = args.explorer_port
    node.start()
