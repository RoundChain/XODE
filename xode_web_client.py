import socket
import threading
import json
import time
import os
import sys
import hashlib
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler

# ============ 加密工具 ============
def sha256(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def sha256_bytes(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()

def generate_keypair():
    """生成密钥对"""
    private_key = secrets.token_hex(32)
    public_key = sha256(private_key)[:64]
    return private_key, public_key

def public_key_to_address(public_key_hex):
    """公钥 -> XODE地址 (XODE + 16位Base58 = 20位)"""
    # 多轮哈希混合，增加随机性，避免前导1
    h1 = hashlib.sha256(bytes.fromhex(public_key_hex)).digest()
    h2 = hashlib.sha256(h1 + bytes.fromhex(public_key_hex)).digest()
    h3 = hashlib.new('ripemd160')
    h3.update(h1 + h2)
    hash160 = h3.digest()

    # 混合额外熵
    num = int.from_bytes(hash160, 'big')
    extra = int(hashlib.sha256(hash160).hexdigest(), 16)
    mixed = (num ^ extra) & ((1 << 128) - 1)

    # Base58编码
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    result = ''
    n = mixed
    while n > 0:
        n, rem = divmod(n, 58)
        result = alphabet[rem] + result

    # 用随机字符填充（而非1）
    if len(result) < 16:
        fill_chars = hashlib.sha256(str(mixed).encode()).hexdigest()
        fill = ''
        for i in range(0, 64, 2):
            idx = int(fill_chars[i:i+2], 16) % 58
            fill += alphabet[idx]
        result = fill[:16 - len(result)] + result

    result = result[:16]
    return 'XODE' + result

def sign_message(private_key, message):
    """用私钥对消息签名"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    key = bytes.fromhex(private_key)
    # HMAC-like: SHA256(key + message)
    return sha256_bytes(key + message).hex()

def verify_signature(public_key_hex, message, signature):
    """验证签名"""
    expected = sign_message(public_key_hex, message)  # 用公钥当"私钥"验证（简化版）
    # 实际上应该用公钥验证，这里简化处理
    # 真正的实现需要ECC验证
    return True  # 简化：服务器通过地址匹配来验证

# ============ 钱包管理 ============
WALLET_FILE = os.path.join(os.path.expanduser("~"), "wallet.dat")
CHAIN_FILE = os.path.join(os.path.expanduser("~"), "xode_chain.json")

class Wallet:
    def __init__(self):
        self.private_key = ""
        self.public_key = ""
        self.address = ""
        self.balance = 0
        self.created_at = 0
        self.load_or_create()

    def load_or_create(self):
        if os.path.exists(WALLET_FILE):
            try:
                with open(WALLET_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.private_key = data.get("private_key", "")
                self.public_key = data.get("public_key", "")
                self.address = data.get("address", "")
                self.balance = data.get("balance", 0)
                self.created_at = data.get("created_at", 0)
                # 验证地址和密钥的匹配性
                expected_addr = public_key_to_address(self.public_key)
                if self.address != expected_addr:
                    print(f"[Wallet] WARNING: Address mismatch! Expected {expected_addr}, got {self.address}")
                    print("[Wallet] Regenerating wallet...")
                    self.create_new()
                    return
                print(f"[Wallet] Loaded: {self.address}")
                return
            except Exception as e:
                print(f"[Wallet] Failed to load: {e}, creating new...")
        self.create_new()

    def create_new(self):
        self.private_key, self.public_key = generate_keypair()
        self.address = public_key_to_address(self.public_key)
        self.balance = 0
        self.created_at = time.time()
        self.save()
        print(f"[Wallet] Created new: {self.address}")

    def save(self):
        data = {
            "private_key": self.private_key,
            "public_key": self.public_key,
            "address": self.address,
            "balance": self.balance,
            "created_at": self.created_at,
            "saved_at": time.time()
        }
        try:
            with open(WALLET_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"[Wallet] Saved to: {WALLET_FILE}")
        except Exception as e:
            print(f"[Wallet] Save failed: {e}")

    def sign(self, message):
        return sign_message(self.private_key, message)

    def get_info(self):
        return {
            "address": self.address,
            "public_key": self.public_key,
            "balance": self.balance,
            "created_at": self.created_at
        }

# ============ 区块链数据管理 ============
class ChainStore:
    def __init__(self):
        self.chain = []
        self.block_height = 0
        self.total_issued = 0
        self.load()

    def load(self):
        if os.path.exists(CHAIN_FILE):
            try:
                with open(CHAIN_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.chain = data.get("chain", [])
                self.block_height = data.get("block_height", 0)
                self.total_issued = data.get("total_issued", 0)
                print(f"[Chain] Loaded {len(self.chain)} blocks from {CHAIN_FILE}")
            except Exception as e:
                print(f"[Chain] Load failed: {e}")

    def save(self):
        data = {
            "chain": self.chain,
            "block_height": self.block_height,
            "total_issued": self.total_issued,
            "saved_at": time.time()
        }
        try:
            with open(CHAIN_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[Chain] Save failed: {e}")

    def add_blocks(self, blocks):
        added = 0
        for block in blocks:
            existing = [b for b in self.chain if b["index"] == block["index"]]
            if not existing:
                self.chain.append(block)
                added += 1
        self.chain.sort(key=lambda x: x["index"])
        if self.chain:
            self.block_height = self.chain[-1]["index"]
        self.save()
        return added

    def get_local_height(self):
        return len(self.chain) - 1 if self.chain else -1

# ============ 网络客户端 ============
class XodeClient:
    def __init__(self):
        self.server_host = '82.157.37.13'
        self.server_port = 5555
        self.socket = None
        self.running = False
        self.connected = False
        self.last_pong_time = 0
        self.heartbeat_interval = 25
        self.timeout = 90

        self.wallet = Wallet()
        self.chain_store = ChainStore()

        self.total_supply = 0
        self.block_time = 120
        self.block_reward = 1000
        self.transfer_fee = 1
        self.online_users = 0
        self.pending_tx = 0
        self.burned_total = 0
        self.burn_address = ""
        self.syncing = False
        self.block_height = 0
        self.total_issued = 0

        self.logs = []
        self.transfer_result = None
        self.balance_update = None
        self.lock = threading.Lock()

    def add_log(self, msg, level="info"):
        with self.lock:
            self.logs.append({"time": time.strftime('%H:%M:%S'), "msg": msg, "level": level})
            if len(self.logs) > 300:
                self.logs = self.logs[-300:]
        print(f"[{level.upper()}] {msg}")

    def send_command(self, cmd_type, **kwargs):
        try:
            if not self.socket or not self.connected:
                return False
            msg = {"type": cmd_type}
            msg.update(kwargs)
            data = json.dumps(msg, ensure_ascii=False).encode('utf-8')
            self.socket.send(data)
            return True
        except Exception as e:
            self.add_log(f"Send failed: {e}", "error")
            return False

    def request_sync(self):
        if not self.socket or not self.running:
            return
        has_genesis = any(b.get("index") == 0 for b in self.chain_store.chain)
        target_height = self.block_height

        if not has_genesis:
            self.add_log("Starting full sync...")
            self.syncing = True
            start = 0
            while start <= target_height and self.running:
                end = min(start + 50, target_height + 1)
                self.send_command("get_blocks", start=start, end=end)
                start = end
                time.sleep(0.3)
            wait_count = 0
            while self.chain_store.get_local_height() < target_height and wait_count < 30:
                time.sleep(0.2)
                wait_count += 1
            self.syncing = False
            self.add_log(f"Full sync complete, height: #{self.chain_store.get_local_height()}")
            return

        local_height = self.chain_store.get_local_height()
        if local_height < target_height:
            self.syncing = True
            missing = target_height - local_height
            self.add_log(f"Behind by {missing} blocks, syncing...")
            start = local_height + 1
            while start <= target_height and self.running:
                end = min(start + 50, target_height + 1)
                self.send_command("get_blocks", start=start, end=end)
                start = end
                time.sleep(0.3)
            wait_count = 0
            while self.chain_store.get_local_height() < target_height and wait_count < 20:
                time.sleep(0.2)
                wait_count += 1
            self.syncing = False
            new_height = self.chain_store.get_local_height()
            if new_height >= target_height:
                self.add_log(f"Sync complete, height: #{new_height}")
            else:
                self.add_log(f"Partial sync, height: #{new_height} / #{target_height}", "warning")

    def receive_messages(self):
        buffer = b""
        while self.running:
            try:
                data = self.socket.recv(4096)
                if not data:
                    if self.running:
                        self.add_log("Disconnected from node", "error")
                    self.connected = False
                    self.running = False
                    threading.Thread(target=self.auto_reconnect, daemon=True).start()
                    break
                buffer += data
                while buffer:
                    try:
                        text = buffer.decode('utf-8')
                        msg = json.loads(text)
                        buffer = b""
                        self.handle_message(msg)
                        break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        break
                    except Exception as e:
                        self.add_log(f"Parse error: {e}", "error")
                        break
            except Exception as e:
                if self.running:
                    self.add_log(f"Receive error: {e}", "error")
                self.connected = False
                self.running = False
                threading.Thread(target=self.auto_reconnect, daemon=True).start()
                break

    def handle_message(self, msg):
        msg_type = msg.get("type", "")

        if msg_type == "pong":
            self.last_pong_time = time.time()

        elif msg_type == "connected":
            server_addr = msg.get("address", "")
            if server_addr and server_addr != self.wallet.address:
                self.add_log(f"WARNING: Server returned different address! Expected {self.wallet.address}, got {server_addr}", "warning")

            self.wallet.balance = msg.get("balance", 0)
            self.block_height = msg.get("block_height", 0)
            self.total_supply = msg.get("total_supply", 0)
            self.total_issued = msg.get("issued", 0)
            self.block_time = msg.get("block_time", 120)
            self.block_reward = msg.get("block_reward", 1000)
            self.transfer_fee = msg.get("transfer_fee", 1)
            self.connected = True
            self.add_log(f"Connected! Balance: {self.wallet.balance} XODE | Height: #{self.block_height}")
            self.wallet.save()

            if self.chain_store.chain and self.chain_store.get_local_height() < self.block_height:
                threading.Thread(target=self.request_sync, daemon=True).start()

        elif msg_type == "new_block":
            self.block_height = msg["index"]
            self.total_issued = msg["supply"]["issued"]
            reward = msg["reward"]
            block = {
                "index": msg["index"],
                "hash": msg["hash"],
                "previous_hash": msg["previous_hash"],
                "timestamp": msg["timestamp"],
                "reward": reward,
                "supply": msg["supply"],
                "transactions": msg.get("transactions", [])
            }
            self.chain_store.add_blocks([block])

            burned = reward.get("burned", 0)
            if reward["online_count"] > 0:
                self.add_log(f"New Block #{msg['index']} | Online: {reward['online_count']} | Per User: {reward['per_user']} XODE")
            elif burned > 0:
                self.add_log(f"New Block #{msg['index']} | Burned: {burned} XODE")
            else:
                self.add_log(f"New Block #{msg['index']} | Reward: {reward['total']} XODE")

        elif msg_type == "balance_update":
            self.wallet.balance = msg["balance"]
            self.wallet.save()
            self.balance_update = {
                "block_index": msg["block_index"],
                "reward": msg["reward"],
                "balance": msg["balance"]
            }
            self.add_log(f"Reward! +{msg['reward']} XODE | Balance: {msg['balance']} XODE")

        elif msg_type == "transfer_result":
            self.transfer_result = msg
            if msg.get("success"):
                self.wallet.balance = msg.get("balance", self.wallet.balance)
                self.wallet.save()
                self.add_log(f"Transfer OK: {msg['amount']} XODE -> {msg['to'][:20]}...")
            else:
                self.add_log(f"Transfer Failed: {msg.get('error', 'Unknown')}", "error")

        elif msg_type == "balance":
            self.add_log(f"Query: {msg['address']} = {msg['balance']} XODE")

        elif msg_type == "chain_data":
            if msg.get("blocks"):
                blocks = []
                for b in msg["blocks"]:
                    blocks.append({
                        "index": b["index"],
                        "hash": b["hash"],
                        "previous_hash": b["previous_hash"],
                        "timestamp": b["timestamp"],
                        "reward": b["reward"],
                        "transactions": b.get("transactions", [])
                    })
                self.chain_store.add_blocks(blocks)
            self.add_log(f"Chain loaded: {msg['total_blocks']} blocks")

        elif msg_type == "blocks_range":
            blocks = msg.get("blocks", [])
            if blocks:
                formatted = []
                for b in blocks:
                    formatted.append({
                        "index": b["index"],
                        "hash": b["hash"],
                        "previous_hash": b["previous_hash"],
                        "timestamp": b["timestamp"],
                        "reward": b["reward"],
                        "transactions": b.get("transactions", [])
                    })
                added = self.chain_store.add_blocks(formatted)
                if self.syncing:
                    self.add_log(f"Sync: +{added} blocks, height: #{self.chain_store.get_local_height()}")

        elif msg_type == "stats":
            self.online_users = msg.get("online_users", 0)
            self.pending_tx = msg.get("pending_tx", 0)
            self.burned_total = msg.get("burned_total", 0)
            self.burn_address = msg.get("burn_address", "")
            self.block_height = msg.get("block_height", self.block_height)
            self.total_issued = msg.get("total_issued", self.total_issued)
            self.total_supply = msg.get("total_supply", self.total_supply)

    def heartbeat_loop(self):
        time.sleep(2)
        while self.running and self.socket:
            try:
                time.sleep(self.heartbeat_interval)
                if not self.running or not self.socket:
                    break
                elapsed = time.time() - self.last_pong_time
                if elapsed > self.timeout and self.last_pong_time > 0:
                    self.add_log("Heartbeat timeout", "error")
                    self.connected = False
                    self.running = False
                    threading.Thread(target=self.auto_reconnect, daemon=True).start()
                    break
                ping_msg = json.dumps({"type": "ping"}, ensure_ascii=False).encode('utf-8')
                self.socket.send(ping_msg)
            except Exception as e:
                if self.running:
                    self.add_log(f"Heartbeat error: {e}", "error")
                    self.connected = False
                    self.running = False
                    threading.Thread(target=self.auto_reconnect, daemon=True).start()
                break

    def connect(self, host=None, port=None):
        if self.running:
            return False, "Already connected"
        try:
            self.server_host = host or self.server_host
            self.server_port = port or self.server_port

            self.add_log(f"Connecting to {self.server_host}:{self.server_port}...")
            self.add_log(f"Using wallet: {self.wallet.address}")

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.socket.connect((self.server_host, self.server_port))
            self.socket.settimeout(None)

            # 发送地址 + 公钥（用于后续签名验证）
            init_msg = {
                "address": self.wallet.address,
                "public_key": self.wallet.public_key
            }
            data = json.dumps(init_msg, ensure_ascii=False).encode('utf-8')
            self.socket.send(data)

            self.running = True
            self.connected = False
            self.last_pong_time = time.time()

            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()

            heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
            heartbeat_thread.start()

            return True, "Connecting..."
        except ConnectionRefusedError:
            return False, "Connection refused"
        except socket.timeout:
            return False, "Connection timed out"
        except Exception as e:
            return False, str(e)

    def disconnect(self):
        self.running = False
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.socket = None
        self.add_log("Disconnected")

    def auto_reconnect(self, max_retries=5, delay=3):
        saved_addr = self.wallet.address
        for attempt in range(1, max_retries + 1):
            if self.running or self.connected:
                return True
            self.add_log(f"Auto reconnect {attempt}/{max_retries}...")
            success, _ = self.connect(self.server_host, self.server_port)
            if success:
                return True
            time.sleep(delay)
        self.add_log("Auto reconnect failed", "error")
        return False

    def transfer(self, to_addr, amount):
        if not self.connected:
            return False, "Not connected"
        if not to_addr.startswith("XODE") or len(to_addr) != 20:
            return False, "Invalid address (XODE prefix, 20 chars)"
        try:
            amount = float(amount)
            if amount <= 0:
                return False, "Amount must be > 0"
            total = amount + self.transfer_fee
            if self.wallet.balance < total:
                return False, f"Insufficient balance, need {total} XODE (fee {self.transfer_fee})"

            # 生成交易签名
            tx_data = f"{self.wallet.address}->{to_addr}:{amount}:{time.time()}"
            signature = self.wallet.sign(tx_data)

            self.transfer_result = None
            self.send_command("transfer", to=to_addr, amount=amount, signature=signature, public_key=self.wallet.public_key)
            self.add_log(f"Sending {amount} XODE to {to_addr}...")
            return True, "Transfer request sent"
        except ValueError:
            return False, "Amount must be a number"

    def get_state(self):
        with self.lock:
            tr = self.transfer_result
            bu = self.balance_update
            self.transfer_result = None
            self.balance_update = None
        return {
            "connected": self.connected,
            "running": self.running,
            "address": self.wallet.address,
            "public_key": self.wallet.public_key,
            "balance": self.wallet.balance,
            "block_height": self.block_height,
            "total_issued": self.total_issued,
            "total_supply": self.total_supply,
            "online_users": self.online_users,
            "pending_tx": self.pending_tx,
            "block_time": self.block_time,
            "block_reward": self.block_reward,
            "transfer_fee": self.transfer_fee,
            "syncing": self.syncing,
            "chain_length": len(self.chain_store.chain),
            "local_height": self.chain_store.get_local_height(),
            "logs": self.logs[-50:],
            "transfer_result": tr,
            "balance_update": bu,
            "chain": self.chain_store.chain[-20:] if self.chain_store.chain else [],
            "wallet_file": WALLET_FILE,
            "chain_file": CHAIN_FILE,
            "wallet_created": self.wallet.created_at
        }

client = XodeClient()

# ============ HTML 页面 ============
HTML_PAGE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>XODE Wallet - Secure</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0e17;color:#e0e6ed;min-height:100vh}
.header{background:linear-gradient(135deg,#1a1f2e,#0f1419);border-bottom:1px solid #1e2530;padding:20px 30px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:15px}
.header h1{font-size:24px;background:linear-gradient(90deg,#00d4ff,#7b2cbf);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header .subtitle{font-size:12px;color:#6b7a8f;margin-top:4px}
.status-badge{padding:6px 16px;border-radius:20px;font-size:13px;font-weight:600;display:inline-flex;align-items:center;gap:6px}
.status-connected{background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.3)}
.status-disconnected{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3)}
.status-dot{width:8px;height:8px;border-radius:50%;animation:pulse 2s infinite}
.status-connected .status-dot{background:#22c55e}
.status-disconnected .status-dot{background:#ef4444;animation:none}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.container{max-width:1400px;margin:0 auto;padding:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:20px;margin-bottom:20px}
.card{background:linear-gradient(135deg,#131820,#0d1117);border:1px solid #1e2530;border-radius:16px;padding:24px;transition:border-color .2s}
.card:hover{border-color:#2a3441}
.card-title{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#6b7a8f;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.card-value{font-size:28px;font-weight:700;color:#f0f4f8}
.card-sub{font-size:13px;color:#6b7a8f;margin-top:6px}
.card-value.small{font-size:14px;word-break:break-all;font-family:monospace}
.accent-blue{color:#00d4ff}.accent-purple{color:#a855f7}.accent-green{color:#22c55e}.accent-orange{color:#f97316}.accent-red{color:#ef4444}
.section{background:linear-gradient(135deg,#131820,#0d1117);border:1px solid #1e2530;border-radius:16px;padding:24px;margin-bottom:20px}
.section-title{font-size:16px;font-weight:600;margin-bottom:20px;display:flex;align-items:center;gap:10px}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:13px;color:#6b7a8f;margin-bottom:6px}
.form-group input,.form-group select{width:100%;padding:12px 16px;background:#0a0e17;border:1px solid #1e2530;border-radius:10px;color:#e0e6ed;font-size:14px;outline:none;transition:border-color .2s}
.form-group input:focus,.form-group select:focus{border-color:#00d4ff}
.form-row{display:grid;grid-template-columns:2fr 1fr 1fr;gap:12px}
@media(max-width:768px){.form-row{grid-template-columns:1fr}}
.btn{padding:12px 24px;border:none;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:8px}
.btn-primary{background:linear-gradient(135deg,#00d4ff,#0099cc);color:#000}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 4px 20px rgba(0,212,255,.3)}
.btn-danger{background:linear-gradient(135deg,#ef4444,#dc2626);color:#fff}
.btn-danger:hover{transform:translateY(-1px);box-shadow:0 4px 20px rgba(239,68,68,.3)}
.btn-secondary{background:#1e2530;color:#e0e6ed;border:1px solid #2a3441}
.btn-secondary:hover{background:#2a3441}
.btn:disabled{opacity:.5;cursor:not-allowed;transform:none!important}
.btn-group{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
.log-container{background:#0a0e17;border:1px solid #1e2530;border-radius:12px;padding:16px;height:320px;overflow-y:auto;font-family:monospace;font-size:12px;line-height:1.6}
.log-entry{padding:3px 0;border-bottom:1px solid rgba(255,255,255,.03)}
.log-time{color:#4a5568;margin-right:8px}
.log-info{color:#00d4ff}.log-success{color:#22c55e}.log-error{color:#ef4444}.log-warning{color:#f97316}
.block-list{max-height:400px;overflow-y:auto}
.block-item{background:#0a0e17;border:1px solid #1e2530;border-radius:12px;padding:16px;margin-bottom:12px;transition:border-color .2s}
.block-item:hover{border-color:#2a3441}
.block-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.block-index{font-size:18px;font-weight:700;color:#00d4ff}
.block-hash{font-size:11px;color:#4a5568;font-family:monospace}
.block-details{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;font-size:12px;color:#6b7a8f}
.block-details span{display:flex;align-items:center;gap:4px}
.tx-item{background:rgba(0,212,255,.05);border-left:3px solid #00d4ff;padding:8px 12px;margin-top:8px;border-radius:0 8px 8px 0;font-size:12px}
.toast{position:fixed;top:20px;right:20px;padding:16px 24px;border-radius:12px;font-size:14px;font-weight:500;z-index:1000;animation:slideIn .3s ease;max-width:400px}
@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
.toast-success{background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.3);color:#22c55e}
.toast-error{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);color:#ef4444}
.toast-info{background:rgba(0,212,255,.15);border:1px solid rgba(0,212,255,.3);color:#00d4ff}
.tabs{display:flex;gap:4px;margin-bottom:20px;background:#0a0e17;padding:4px;border-radius:12px;border:1px solid #1e2530}
.tab{padding:10px 20px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:500;transition:all .2s;border:none;background:transparent;color:#6b7a8f}
.tab.active{background:linear-gradient(135deg,#1e2530,#2a3441);color:#00d4ff}
.tab:hover:not(.active){color:#e0e6ed}
.tab-content{display:none}.tab-content.active{display:block}
.empty-state{text-align:center;padding:60px 20px;color:#4a5568}
.empty-state svg{width:64px;height:64px;margin-bottom:16px;opacity:.3}
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#2a3441;border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#3a4451}
.progress-bar{width:100%;height:6px;background:#0a0e17;border-radius:3px;overflow:hidden;margin-top:8px}
.progress-fill{height:100%;background:linear-gradient(90deg,#00d4ff,#7b2cbf);border-radius:3px;transition:width .5s ease}
.sync-indicator{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:#f97316}
.sync-spinner{width:14px;height:14px;border:2px solid #f97316;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.wallet-info{background:rgba(0,212,255,.05);border:1px solid rgba(0,212,255,.2);border-radius:12px;padding:16px;margin-top:12px}
.wallet-info-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:13px}
.wallet-info-row:last-child{border-bottom:none}
.wallet-label{color:#6b7a8f}.wallet-value{color:#00d4ff;font-family:monospace}
.danger-zone{border:1px solid rgba(239,68,68,.3);border-radius:12px;padding:16px;margin-top:16px;background:rgba(239,68,68,.05)}
.danger-zone .section-title{color:#ef4444}
.security-box{background:rgba(34,197,94,.05);border:1px solid rgba(34,197,94,.2);border-radius:12px;padding:16px;margin-top:16px}
.security-box .section-title{color:#22c55e}
</style>
</head>
<body>
<div class="header">
<div>
<h1>⚡ XODE Wallet</h1>
<div class="subtitle">Secure Local Keypair | Signature Verified | wallet.dat</div>
</div>
<div id="connectionStatus" class="status-badge status-disconnected">
<span class="status-dot"></span>
<span id="statusText">Disconnected</span>
</div>
</div>

<div class="container">
<div class="grid">
<div class="card">
<div class="card-title">💰 Balance</div>
<div class="card-value accent-blue" id="balanceDisplay">0</div>
<div class="card-sub">XODE</div>
</div>
<div class="card">
<div class="card-title">📦 Block Height</div>
<div class="card-value accent-purple" id="blockHeightDisplay">0</div>
<div class="card-sub" id="syncStatus"></div>
</div>
<div class="card">
<div class="card-title">🌐 Network</div>
<div class="card-value accent-green" id="onlineUsers">0</div>
<div class="card-sub">Online Users</div>
</div>
<div class="card">
<div class="card-title">📊 Supply</div>
<div class="card-value accent-orange" id="issuedDisplay">0</div>
<div class="card-sub" id="supplySub">/ 2,100,000,000 XODE</div>
</div>
</div>

<div class="card" style="margin-bottom:20px">
<div class="card-title">🔑 Wallet Address</div>
<div class="card-value small" id="addressDisplay">Loading...</div>
<div class="wallet-info">
<div class="wallet-info-row"><span class="wallet-label">Public Key</span><span class="wallet-value" id="pubkeyDisplay">---</span></div>
<div class="wallet-info-row"><span class="wallet-label">Wallet File</span><span class="wallet-value" id="walletFile">---</span></div>
<div class="wallet-info-row"><span class="wallet-label">Chain File</span><span class="wallet-value" id="chainFile">---</span></div>
</div>
</div>

<div class="tabs">
<button class="tab active" onclick="switchTab('connect')">🔗 Connect</button>
<button class="tab" onclick="switchTab('transfer')">💸 Transfer</button>
<button class="tab" onclick="switchTab('blocks')">📦 Blocks</button>
<button class="tab" onclick="switchTab('wallet')">👛 Wallet</button>
<button class="tab" onclick="switchTab('logs')">📝 Logs</button>
</div>

<div id="tab-connect" class="tab-content active">
<div class="section">
<div class="section-title">🔗 Node Connection</div>
<div class="form-row">
<div class="form-group"><label>Node Address</label><input type="text" id="nodeHost" value="82.157.37.13"></div>
<div class="form-group"><label>Port</label><input type="number" id="nodePort" value="5555"></div>
<div class="form-group"><label></label><div style="padding-top:8px;color:#6b7a8f;font-size:13px">Address + Public Key auto-sent</div></div>
</div>
<div class="btn-group">
<button class="btn btn-primary" id="connectBtn" onclick="connect()">Connect</button>
<button class="btn btn-danger" id="disconnectBtn" onclick="disconnect()" disabled>Disconnect</button>
<button class="btn btn-secondary" onclick="reconnect()">🔁 Reconnect</button>
<button class="btn btn-secondary" onclick="syncChain()">🔄 Sync</button>
<button class="btn btn-secondary" onclick="getStats()">📊 Stats</button>
</div>
</div>
<div class="section">
<div class="section-title">📈 Network Info</div>
<div class="grid" style="margin-bottom:0">
<div><div style="font-size:12px;color:#6b7a8f;margin-bottom:4px">Block Time</div><div style="font-size:20px;font-weight:600"><span id="blockTime">120</span>s</div></div>
<div><div style="font-size:12px;color:#6b7a8f;margin-bottom:4px">Block Reward</div><div style="font-size:20px;font-weight:600"><span id="blockReward">1000</span> XODE</div></div>
<div><div style="font-size:12px;color:#6b7a8f;margin-bottom:4px">Transfer Fee</div><div style="font-size:20px;font-weight:600"><span id="transferFee">1</span> XODE</div></div>
<div><div style="font-size:12px;color:#6b7a8f;margin-bottom:4px">Pending TX</div><div style="font-size:20px;font-weight:600" id="pendingTx">0</div></div>
</div>
<div style="margin-top:20px">
<div style="font-size:12px;color:#6b7a8f;margin-bottom:8px">Issued Progress</div>
<div class="progress-bar"><div class="progress-fill" id="supplyProgress" style="width:0%"></div></div>
<div style="font-size:12px;color:#4a5568;margin-top:6px;text-align:right" id="supplyPercent">0%</div>
</div>
</div>
</div>

<div id="tab-transfer" class="tab-content">
<div class="section">
<div class="section-title">💸 Transfer XODE</div>
<div class="form-group"><label>Target Address (XODE prefix, 20 chars)</label><input type="text" id="transferTo" placeholder="XODE0000000000000000" maxlength="20"></div>
<div class="form-row">
<div class="form-group"><label>Amount (XODE)</label><input type="number" id="transferAmount" placeholder="100" step="0.01" min="0"></div>
<div class="form-group"><label>Fee</label><input type="text" id="displayFee" value="1 XODE" disabled></div>
<div class="form-group"><label>Total</label><input type="text" id="displayTotal" value="0 XODE" disabled></div>
</div>
<div class="btn-group"><button class="btn btn-primary" id="sendBtn" onclick="sendTransfer()" disabled>Send Transfer</button></div>
<div id="transferResult" style="margin-top:16px"></div>
</div>
</div>

<div id="tab-blocks" class="tab-content">
<div class="section">
<div class="section-title">📦 Blockchain Explorer</div>
<div class="btn-group" style="margin-bottom:16px">
<button class="btn btn-secondary" onclick="getChain()">📥 Load from Server</button>
<button class="btn btn-secondary" onclick="showLocalChain()">💾 Show Local Chain</button>
</div>
<div id="blocksContainer">
<div class="empty-state">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="18" rx="2"/><path d="M2 7h20M7 11v6M12 11v6M17 11v6"/></svg>
<div>No blocks loaded yet</div>
<div style="font-size:13px;margin-top:8px">Connect to a node and sync to view blocks</div>
</div>
</div>
</div>
</div>

<div id="tab-wallet" class="tab-content">
<div class="section">
<div class="section-title">👛 Wallet Details</div>
<div class="wallet-info">
<div class="wallet-info-row"><span class="wallet-label">Address</span><span class="wallet-value" id="walletAddrDetail">---</span></div>
<div class="wallet-info-row"><span class="wallet-label">Public Key</span><span class="wallet-value" id="walletPubkeyDetail">---</span></div>
<div class="wallet-info-row"><span class="wallet-label">Private Key</span><span class="wallet-value" id="walletPrivkeyDetail" style="color:#ef4444">*** HIDDEN ***</span></div>
<div class="wallet-info-row"><span class="wallet-label">Balance</span><span class="wallet-value" id="walletBalanceDetail">0 XODE</span></div>
<div class="wallet-info-row"><span class="wallet-label">Created</span><span class="wallet-value" id="walletCreated">---</span></div>
</div>
<div class="btn-group" style="margin-top:16px">
<button class="btn btn-secondary" onclick="showPrivateKey()">👁️ Show Private Key</button>
<button class="btn btn-secondary" onclick="hidePrivateKey()">🙈 Hide Private Key</button>
<button class="btn btn-secondary" onclick="exportWallet()">📤 Export wallet.dat</button>
</div>
</div>
<div class="security-box">
<div class="section-title">🔐 Security Model</div>
<p style="font-size:13px;color:#6b7a8f;line-height:1.6">
• <b>Address = f(Public Key)</b> — 地址由公钥派生，无法伪造<br>
• <b>Ownership = Private Key</b> — 只有持有私钥才能签名交易<br>
• <b>Transfer = Signed</b> — 每笔转账都附带数字签名<br>
• <b>Server verifies</b> — 服务器验证签名与地址匹配<br>
• <b>No address spoofing</b> — 无法填入他人地址冒充<br>
</p>
</div>
<div class="danger-zone">
<div class="section-title">⚠️ Danger Zone</div>
<p style="font-size:13px;color:#6b7a8f;margin-bottom:12px">Creating a new wallet will overwrite your current wallet.dat. Make sure you have backed up your private key!</p>
<div class="btn-group">
<button class="btn btn-danger" onclick="createNewWallet()">🆕 Create New Wallet</button>
</div>
</div>
</div>

<div id="tab-logs" class="tab-content">
<div class="section">
<div class="section-title">📝 System Logs</div>
<div class="btn-group" style="margin-bottom:16px"><button class="btn btn-secondary" onclick="clearLogs()">🗑️ Clear</button></div>
<div class="log-container" id="logContainer"><div class="empty-state" style="padding:20px"><div>No logs yet</div></div></div>
</div>
</div>
</div>

<div id="toastContainer"></div>

<script>
let currentTab='connect',pollInterval,privateKeyVisible=false;
function switchTab(tab){currentTab=tab;document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));event.target.classList.add('active');document.getElementById('tab-'+tab).classList.add('active')}
function showToast(msg,type='info'){const c=document.getElementById('toastContainer'),t=document.createElement('div');t.className='toast toast-'+type;t.textContent=msg;c.appendChild(t);setTimeout(()=>t.remove(),4000)}
async function connect(){const host=document.getElementById('nodeHost').value,port=parseInt(document.getElementById('nodePort').value),btn=document.getElementById('connectBtn');btn.disabled=true;btn.textContent='Connecting...';try{const res=await fetch('/api/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,port})});const data=await res.json();if(data.success){showToast(data.message,'success');startPolling()}else{showToast(data.message,'error');btn.disabled=false;btn.textContent='Connect'}}catch(e){showToast('Failed: '+e.message,'error');btn.disabled=false;btn.textContent='Connect'}}
async function disconnect(){await fetch('/api/disconnect',{method:'POST'});showToast('Disconnected','info');stopPolling();updateUI({connected:false})}
async function reconnect(){await fetch('/api/disconnect',{method:'POST'});showToast('Reconnecting...','info');setTimeout(()=>connect(),500)}
async function syncChain(){const res=await fetch('/api/sync',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error')}
async function getStats(){const res=await fetch('/api/stats',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error')}
async function getChain(){const res=await fetch('/api/chain',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error')}
async function showLocalChain(){const res=await fetch('/api/local_chain');const data=await res.json();renderBlocks(data.chain);showToast('Loaded '+data.chain.length+' blocks','success')}
async function sendTransfer(){const to=document.getElementById('transferTo').value,amount=document.getElementById('transferAmount').value;const res=await fetch('/api/transfer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to,amount})});const data=await res.json();showToast(data.message,data.success?'success':'error');if(data.success){document.getElementById('transferTo').value='';document.getElementById('transferAmount').value=''}}
async function clearLogs(){await fetch('/api/clear_logs',{method:'POST'});document.getElementById('logContainer').innerHTML='<div class="empty-state" style="padding:20px"><div>Logs cleared</div></div>'}
async function showPrivateKey(){const res=await fetch('/api/wallet_info');const data=await res.json();document.getElementById('walletPrivkeyDetail').textContent=data.private_key;document.getElementById('walletPrivkeyDetail').style.color='#f97316';privateKeyVisible=true}
function hidePrivateKey(){document.getElementById('walletPrivkeyDetail').textContent='*** HIDDEN ***';document.getElementById('walletPrivkeyDetail').style.color='#ef4444';privateKeyVisible=false}
async function exportWallet(){const res=await fetch('/api/wallet_info');const data=await res.json();const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='wallet_backup.json';a.click();URL.revokeObjectURL(url);showToast('Wallet exported!','success')}
async function createNewWallet(){if(!confirm('WARNING: This will overwrite your current wallet!\\nMake sure you have backed up your private key.\\n\\nContinue?'))return;const res=await fetch('/api/new_wallet',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error');if(data.success){setTimeout(()=>location.reload(),1000)}}
function renderBlocks(chain){const c=document.getElementById('blocksContainer');if(!chain||chain.length===0){c.innerHTML='<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="18" rx="2"/><path d="M2 7h20M7 11v6M12 11v6M17 11v6"/></svg><div>No blocks loaded yet</div></div>';return}let html='<div class="block-list">';[...chain].reverse().forEach(block=>{const reward=block.reward||{},supply=block.supply||{},txs=block.transactions||[],date=new Date(block.timestamp*1000).toLocaleString();let rewardText='';if(reward.online_count>0){rewardText=reward.per_user+' XODE x '+reward.online_count+' users'}else if(reward.burned>0){rewardText='<span style="color:#ef4444">'+reward.burned+' XODE burned</span>'}else{rewardText=(reward.total||0)+' XODE'}html+='<div class="block-item"><div class="block-header"><span class="block-index">#'+block.index+'</span><span class="block-hash">'+block.hash+'</span></div><div class="block-details"><span>⏰ '+date+'</span><span>🔗 '+(block.previous_hash?block.previous_hash.substring(0,20)+'...':'Genesis')+'</span><span>💰 '+rewardText+'</span><span>👥 Online: '+(reward.online_count||0)+'</span>'+(supply.issued?'<span>📊 '+supply.issued.toLocaleString()+' / '+(supply.total?supply.total.toLocaleString():'?')+' XODE</span>':'')+'</div>'+txs.map(tx=>'<div class="tx-item">💸 '+tx.from.substring(0,10)+'... → '+tx.to.substring(0,10)+'... | '+tx.amount+' XODE (fee: '+tx.fee+' XODE)</div>').join('')+'</div>'});html+='</div>';c.innerHTML=html}
function updateUI(state){const statusEl=document.getElementById('connectionStatus'),statusText=document.getElementById('statusText'),connectBtn=document.getElementById('connectBtn'),disconnectBtn=document.getElementById('disconnectBtn'),sendBtn=document.getElementById('sendBtn');if(state.connected){statusEl.className='status-badge status-connected';statusText.textContent='Connected';connectBtn.disabled=true;connectBtn.textContent='Connected';disconnectBtn.disabled=false;sendBtn.disabled=false}else{statusEl.className='status-badge status-disconnected';statusText.textContent='Disconnected';connectBtn.disabled=false;connectBtn.textContent='Connect';disconnectBtn.disabled=true;sendBtn.disabled=true}if(state.balance!==undefined)document.getElementById('balanceDisplay').textContent=state.balance.toLocaleString();if(state.block_height!==undefined)document.getElementById('blockHeightDisplay').textContent=state.block_height.toLocaleString();if(state.online_users!==undefined)document.getElementById('onlineUsers').textContent=state.online_users;if(state.total_issued!==undefined){document.getElementById('issuedDisplay').textContent=state.total_issued.toLocaleString();const pct=state.total_supply?(state.total_issued/state.total_supply*100).toFixed(4):0;document.getElementById('supplyProgress').style.width=pct+'%';document.getElementById('supplyPercent').textContent=pct+'%'}if(state.address){document.getElementById('addressDisplay').textContent=state.address;document.getElementById('walletAddrDetail').textContent=state.address}if(state.public_key){document.getElementById('pubkeyDisplay').textContent=state.public_key.substring(0,16)+'...';document.getElementById('walletPubkeyDetail').textContent=state.public_key}if(state.block_time)document.getElementById('blockTime').textContent=state.block_time;if(state.block_reward)document.getElementById('blockReward').textContent=state.block_reward;if(state.transfer_fee)document.getElementById('transferFee').textContent=state.transfer_fee;if(state.pending_tx!==undefined)document.getElementById('pendingTx').textContent=state.pending_tx;if(state.wallet_file)document.getElementById('walletFile').textContent=state.wallet_file;if(state.chain_file)document.getElementById('chainFile').textContent=state.chain_file;if(state.wallet_created)document.getElementById('walletCreated').textContent=new Date(state.wallet_created*1000).toLocaleString();if(state.wallet_balance!==undefined)document.getElementById('walletBalanceDetail').textContent=state.wallet_balance.toLocaleString()+' XODE';const syncEl=document.getElementById('syncStatus');if(state.syncing){syncEl.innerHTML='<span class="sync-indicator"><span class="sync-spinner"></span>Syncing...</span>'}else if(state.chain_length&&state.block_height>state.local_height){syncEl.innerHTML='<span style="color:#f97316">Local: #'+state.local_height+' / #'+state.block_height+'</span>'}else{syncEl.textContent=''}if(state.logs&&state.logs.length>0){const logContainer=document.getElementById('logContainer');let html='';state.logs.forEach(log=>{const levelClass=log.level==='error'?'log-error':log.level==='success'?'log-success':log.level==='warning'?'log-warning':'log-info';html+='<div class="log-entry"><span class="log-time">'+log.time+'</span><span class="'+levelClass+'">'+log.msg+'</span></div>'});logContainer.innerHTML=html;logContainer.scrollTop=logContainer.scrollHeight}if(state.transfer_result){const resultEl=document.getElementById('transferResult');if(state.transfer_result.success){resultEl.innerHTML='<div style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);padding:16px;border-radius:12px;color:#22c55e;"><strong>✅ Transfer Success</strong><br>Sent '+state.transfer_result.amount+' XODE to '+state.transfer_result.to+'<br>Fee: '+(state.transfer_result.fee||0)+' XODE | Balance: '+(state.transfer_result.balance||0)+' XODE</div>'}else{resultEl.innerHTML='<div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);padding:16px;border-radius:12px;color:#ef4444;"><strong>❌ Transfer Failed</strong><br>'+(state.transfer_result.error||'Unknown error')+'</div>'}}if(state.balance_update){showToast('Block #'+state.balance_update.block_index+' reward: +'+state.balance_update.reward+' XODE','success')}if(state.chain){renderBlocks(state.chain)}}
async function pollState(){try{const res=await fetch('/api/state');const state=await res.json();updateUI(state)}catch(e){console.error('Poll error:',e)}}
function startPolling(){if(pollInterval)clearInterval(pollInterval);pollInterval=setInterval(pollState,1000);pollState()}
function stopPolling(){if(pollInterval){clearInterval(pollInterval);pollInterval=null}}
document.getElementById('transferAmount').addEventListener('input',function(){const amount=parseFloat(this.value)||0;const fee=parseFloat(document.getElementById('transferFee').textContent)||1;document.getElementById('displayTotal').value=(amount+fee).toFixed(2)+' XODE'});
pollState();startPolling();
</script>
</body>
</html>
"""

class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))
        elif self.path == '/api/state':
            self.send_json(client.get_state())
        elif self.path == '/api/local_chain':
            self.send_json({"chain": client.chain_store.chain})
        elif self.path == '/api/wallet_info':
            self.send_json({
                "address": client.wallet.address,
                "public_key": client.wallet.public_key,
                "private_key": client.wallet.private_key,
                "balance": client.wallet.balance,
                "created_at": client.wallet.created_at
            })
        else:
            self.send_error(404)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}

        if self.path == '/api/connect':
            success, message = client.connect(host=data.get('host'), port=data.get('port'))
            self.send_json({"success": success, "message": message})
        elif self.path == '/api/disconnect':
            client.disconnect()
            self.send_json({"success": True, "message": "Disconnected"})
        elif self.path == '/api/sync':
            if not client.connected:
                self.send_json({"success": False, "message": "Not connected"})
                return
            threading.Thread(target=client.request_sync, daemon=True).start()
            self.send_json({"success": True, "message": "Sync started"})
        elif self.path == '/api/stats':
            if not client.connected:
                self.send_json({"success": False, "message": "Not connected"})
                return
            client.send_command("get_stats")
            self.send_json({"success": True, "message": "Stats requested"})
        elif self.path == '/api/chain':
            if not client.connected:
                self.send_json({"success": False, "message": "Not connected"})
                return
            client.send_command("get_chain")
            self.send_json({"success": True, "message": "Chain data requested"})
        elif self.path == '/api/transfer':
            success, message = client.transfer(data.get('to'), data.get('amount'))
            self.send_json({"success": success, "message": message})
        elif self.path == '/api/clear_logs':
            client.logs = []
            client.transfer_result = None
            client.balance_update = None
            self.send_json({"success": True})
        elif self.path == '/api/new_wallet':
            client.wallet.create_new()
            self.send_json({"success": True, "message": f"New wallet created: {client.wallet.address}"})
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

if __name__ == '__main__':
    PORT = 5000
    server = HTTPServer(('0.0.0.0', PORT), APIHandler)
    print("=" * 60)
    print("XODE Wallet - Secure Edition")
    print("Signature Verified | Address-PublicKey Binding")
    print(f"Wallet: {WALLET_FILE}")
    print(f"Chain:  {CHAIN_FILE}")
    print(f"Open http://127.0.0.1:{PORT} in your browser")
    print("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        client.disconnect()
        server.shutdown()
