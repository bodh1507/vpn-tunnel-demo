# vpn_client.py
import socket
import argparse
import os
import time
import threading
from vpn_common import *
from cryptography.hazmat.primitives.asymmetric import ed25519

CLIENT_ID = b"vpn-client-demo"

def save_keypair(priv: ed25519.Ed25519PrivateKey, priv_path: str, pub_path: str):
    with open(priv_path, "wb") as f:
        f.write(ed25519_serialize_priv(priv))
    with open(pub_path, "wb") as f:
        f.write(ed25519_serialize_pub(priv.public_key()))

def load_keypair(priv_file: str, pub_file: str):
    with open(priv_file, "rb") as f:
        priv = ed25519_load_priv(f.read())
    with open(pub_file, "rb") as f:
        pub = ed25519_load_pub(f.read())
    return priv, pub

class VPNClient:
    def __init__(self, server_ip, server_port, priv: ed25519.Ed25519PrivateKey, server_pub_bytes: bytes = None):
        self.server = (server_ip, server_port)
        self.priv = priv
        self.pub = priv.public_key()
        self.server_pub_bytes = server_pub_bytes
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.key_state: KeyState = None
        self.lock = threading.Lock()
        self.running = True
        self.rekey_lock = threading.Lock()
        self.rekey_new_priv = None

    def handshake(self):
        x_priv, x_pub = generate_x25519_keypair()
        x_pub_bytes = x25519_serialize_pub(x_pub)
        client_nonce = os.urandom(16)
        to_sign = CLIENT_ID + x_pub_bytes + client_nonce
        signature = self.priv.sign(to_sign)
        client_ed_pub = ed25519_serialize_pub(self.pub)
        packet = bytes([len(CLIENT_ID)]) + CLIENT_ID + client_ed_pub + x_pub_bytes + client_nonce + len(signature).to_bytes(2, 'big') + signature
        self.sock.sendto(packet, self.server)
        print("[*] Sent handshake init")

        data, _ = self.sock.recvfrom(65535)
        off = 0
        sid_len = data[off]; off += 1
        sid = data[off:off+sid_len]; off += sid_len
        server_ed_pub = data[off:off+32]; off += 32
        server_xpub = data[off:off+32]; off += 32
        server_nonce = data[off:off+16]; off += 16
        sig_len = int.from_bytes(data[off:off+2], 'big'); off += 2
        sig = data[off:off+sig_len]; off += sig_len

        print(f"[*] Received handshake response id={sid}")

        if self.server_pub_bytes:
            server_pub = ed25519_load_pub(self.server_pub_bytes)
            server_pub.verify(sig, sid + server_xpub + server_nonce)
        else:
            server_pub = ed25519_load_pub(server_ed_pub)
            try:
                server_pub.verify(sig, sid + server_xpub + server_nonce)
            except Exception as e:
                print("[!] server signature verify failed (demo), continuing:", e)

        shared = x_priv.exchange(x25519_load_pub(server_xpub))
        session_key = hkdf_sha256(shared)
        self.key_state = KeyState(key=session_key)
        print("[*] Handshake complete, session key ready")

    def send_encrypted(self, payload: bytes, msg_type=MSG_TYPE_DATA):
        ks = self.key_state
        if ks is None:
            raise RuntimeError("No session key")
        nonce = ks.nonce_counter.next()
        aad = struct.pack(HEADER_FMT, ks.send_seq, msg_type)
        ct = aesgcm_encrypt(ks.key, nonce, payload, aad)
        pkt = pack_message(ks.send_seq, msg_type, nonce, ct)
        self.sock.sendto(pkt, self.server)
        with self.lock:
            ks.send_seq += 1
            ks.bytes_transferred += len(ct)
        if ks.bytes_transferred > REKEY_BYTES or (time.time() - ks.last_rekey_time) > REKEY_SECONDS:
            threading.Thread(target=self.initiate_rekey, daemon=True).start()

    def receive_loop(self):
        while self.running:
            try:
                data, peer = self.sock.recvfrom(65535)
            except Exception as e:
                print("[-] recv error:", e)
                break
            try:
                seq, msg_type, nonce, ciphertext = unpack_message(data)
            except Exception:
                print("[-] malformed/non-encrypted packet")
                continue
            ks = self.key_state
            if ks is None:
                print("[-] no key yet; dropping")
                continue
            aad = struct.pack(HEADER_FMT, seq, msg_type)
            try:
                plain = aesgcm_decrypt(ks.key, nonce, ciphertext, aad)
            except Exception as e:
                print("[-] decrypt failed:", e)
                continue
            with self.lock:
                ks.recv_seq += 1
            if msg_type == MSG_TYPE_DATA:
                print(f"[SERVER] {plain[:200]!r}")
            elif msg_type == MSG_TYPE_REKEY_REQ:
                print("[*] Received REKEY_REQ")
                if len(plain) < 64:
                    print("[-] bad rekey_req len")
                    continue
                their_new_xpub = plain[:32]
                their_hmac = plain[32:64]
                expected = hmac_sha256(ks.key, REKEY_HMAC_INFO + their_new_xpub)
                if not secure_compare(expected, their_hmac):
                    print("[-] rekey hmac invalid — ignoring")
                    continue
                our_new_priv, our_new_pub = generate_x25519_keypair()
                shared = our_new_priv.exchange(x25519_load_pub(their_new_xpub))
                new_key = hkdf_sha256(shared, info=b"REKEY")
                confirm = hmac_sha256(new_key, REKEY_CONFIRM_INFO)
                plain_resp = x25519_serialize_pub(our_new_pub) + confirm
                self.send_encrypted(plain_resp, msg_type=MSG_TYPE_REKEY_RESP)
                with self.lock:
                    ks.key = new_key
                    ks.last_rekey_time = time.time()
                    ks.bytes_transferred = 0
                print("[*] Rekey responder done.")
            elif msg_type == MSG_TYPE_REKEY_RESP:
                print("[*] Received REKEY_RESP")
                if len(plain) < 64:
                    print("[-] bad rekey_resp len")
                    continue
                their_new_xpub = plain[:32]
                their_confirm = plain[32:64]
                with self.rekey_lock:
                    if self.rekey_new_priv is None:
                        print("[-] unexpected rekey_resp")
                        continue
                    shared = self.rekey_new_priv.exchange(x25519_load_pub(their_new_xpub))
                    new_key = hkdf_sha256(shared, info=b"REKEY")
                    expected_confirm = hmac_sha256(new_key, REKEY_CONFIRM_INFO)
                    if not secure_compare(expected_confirm, their_confirm):
                        print("[-] rekey confirm mismatch")
                        self.rekey_new_priv = None
                        continue
                    with self.lock:
                        ks.key = new_key
                        ks.last_rekey_time = time.time()
                        ks.bytes_transferred = 0
                    self.rekey_new_priv = None
                    print("[*] Rekey complete (initiator).")
            elif msg_type == MSG_TYPE_TERMINATE:
                print("[*] Terminate received")
                self.running = False

    def initiate_rekey(self, timeout=5.0):
        with self.rekey_lock:
            if self.rekey_new_priv is not None:
                return
            ks = self.key_state
            if ks is None:
                return
            print("[*] Initiating rekey")
            new_priv, new_pub = generate_x25519_keypair()
            new_pub_bytes = x25519_serialize_pub(new_pub)
            tag = hmac_sha256(ks.key, REKEY_HMAC_INFO + new_pub_bytes)
            plain = new_pub_bytes + tag
            self.send_encrypted(plain, msg_type=MSG_TYPE_REKEY_REQ)
            self.rekey_new_priv = new_priv
        start = time.time()
        while time.time() - start < timeout:
            with self.rekey_lock:
                if self.rekey_new_priv is None:
                    return
            time.sleep(0.1)
        with self.rekey_lock:
            self.rekey_new_priv = None
        print("[-] Rekey timed out")

    def start(self):
        self.handshake()
        t = threading.Thread(target=self.receive_loop, daemon=True)
        t.start()
        i = 0
        try:
            while self.running:
                payload = f"virtual-packet-{i}".encode()
                self.send_encrypted(payload, MSG_TYPE_DATA)
                i += 1
                time.sleep(1)
        except KeyboardInterrupt:
            print("[*] KeyboardInterrupt, terminating")
            self.running = False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-ip", default="127.0.0.1")
    parser.add_argument("--server-port", type=int, default=5000)
    parser.add_argument("--priv", default="client_ed25519_priv.bin")
    parser.add_argument("--pub", default="client_ed25519_pub.bin")
    parser.add_argument("--generate-keys", action="store_true")
    parser.add_argument("--pin-server-pub", default=None)
    args = parser.parse_args()

    if args.generate_keys:
        priv, pub = generate_ed25519_keypair()
        save_keypair(priv, args.priv, args.pub)
        print("[*] Generated client keys.")
        exit(0)

    if not os.path.exists(args.priv) or not os.path.exists(args.pub):
        print("[-] Missing client keys. Run --generate-keys first.")
        exit(1)

    priv, pub = load_keypair(args.priv, args.pub)
    pinned = None
    if args.pin_server_pub:
        pinned = open(args.pin_server_pub, "rb").read()
    client = VPNClient(args.server_ip, args.server_port, priv, server_pub_bytes=pinned)
    client.start()
