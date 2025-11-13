# vpn_server.py
import socket
import argparse
import os
import time
import threading
from vpn_common import *
from cryptography.hazmat.primitives.asymmetric import ed25519

SERVER_ID = b"vpn-server-demo"

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

class ClientSession:
    def __init__(self, peer_addr, server_priv):
        self.peer = peer_addr
        self.server_priv = server_priv
        self.server_pub = server_priv.public_key()
        self.session: KeyState = None
        self.lock = threading.Lock()

class VPNServer:
    def __init__(self, bind_ip: str, bind_port: int, priv: ed25519.Ed25519PrivateKey):
        self.addr = (bind_ip, bind_port)
        self.priv = priv
        self.pub = priv.public_key()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)
        self.sessions = {}
        self.running = True
        print(f"[+] Server listening on {self.addr}")

    def start(self):
        while self.running:
            try:
                data, peer = self.sock.recvfrom(65535)
                threading.Thread(target=self.handle_packet, args=(data, peer), daemon=True).start()
            except Exception as e:
                print("[-] recv error:", e)

    def handle_packet(self, data: bytes, peer):
        session = self.sessions.get(peer)
        if session and session.session:
            # Encrypted path
            try:
                seq, msg_type, nonce, ciphertext = unpack_message(data)
            except Exception:
                print("[-] malformed packet from", peer)
                return
            ks = session.session
            aad = struct.pack(HEADER_FMT, seq, msg_type)
            try:
                plain = aesgcm_decrypt(ks.key, nonce, ciphertext, aad)
            except Exception:
                print("[-] decrypt failed for", peer)
                return
            with session.lock:
                ks.recv_seq += 1
            if msg_type == MSG_TYPE_DATA:
                print(f"[{peer}] DATA: {plain[:120]!r}")
                # echo back
                self.send_encrypted(peer, b"echo:" + plain)
                with session.lock:
                    ks.bytes_transferred += len(ciphertext)
                if ks.bytes_transferred > REKEY_BYTES or (time.time() - ks.last_rekey_time) > REKEY_SECONDS:
                    threading.Thread(target=self.initiate_rekey, args=(session,), daemon=True).start()
            elif msg_type == MSG_TYPE_REKEY_REQ:
                print(f"[*] Rekey request from {peer}")
                if len(plain) < 64:
                    print("[-] bad rekey_req len")
                    return
                new_xpub = plain[:32]
                provided_hmac = plain[32:64]
                expected = hmac_sha256(ks.key, REKEY_HMAC_INFO + new_xpub)
                if not secure_compare(expected, provided_hmac):
                    print("[-] Rekey HMAC invalid — ignoring (possible spoof)")
                    return
                # derive new key
                new_priv, new_pub = generate_x25519_keypair()
                shared = new_priv.exchange(x25519_load_pub(new_xpub))
                new_key = hkdf_sha256(shared, info=b"REKEY")
                new_pub_bytes = x25519_serialize_pub(new_pub)
                confirm = hmac_sha256(new_key, REKEY_CONFIRM_INFO)
                resp_plain = new_pub_bytes + confirm
                # send response under current key
                self.send_encrypted(peer, resp_plain, msg_type=MSG_TYPE_REKEY_RESP, session=session)
                # swap keys
                with session.lock:
                    session.session.key = new_key
                    session.session.last_rekey_time = time.time()
                    session.session.bytes_transferred = 0
                print(f"[*] Rekey responder done for {peer}")
            elif msg_type == MSG_TYPE_REKEY_RESP:
                print(f"[*] Rekey response from {peer} (logged)")
            elif msg_type == MSG_TYPE_TERMINATE:
                print(f"[*] Terminate from {peer}")
                self.sessions.pop(peer, None)
            return

        # Handshake expected (cleartext)
        try:
            off = 0
            client_id_len = data[off]; off += 1
            client_id = data[off:off+client_id_len]; off += client_id_len
            client_ed_pub = data[off:off+32]; off += 32
            client_xpub = data[off:off+32]; off += 32
            client_nonce = data[off:off+16]; off += 16
            sig_len = int.from_bytes(data[off:off+2], 'big'); off += 2
            signature = data[off:off+sig_len]; off += sig_len
        except Exception as e:
            print("[-] malformed handshake from", peer, e)
            return

        print(f"[+] Handshake from {client_id} @ {peer}")

        # Verify signature over (client_id || client_xpub || client_nonce)
        try:
            client_pub = ed25519_load_pub(client_ed_pub)
            client_pub.verify(signature, client_id + client_xpub + client_nonce)
        except Exception as e:
            print("[-] client sig verify failed:", e)
            return

        # finish handshake: compute shared secret
        server_x_priv, server_x_pub = generate_x25519_keypair()
        shared = server_x_priv.exchange(x25519_load_pub(client_xpub))
        session_key = hkdf_sha256(shared)
        ks = KeyState(key=session_key)
        sess = ClientSession(peer, self.priv)
        sess.session = ks
        self.sessions[peer] = sess

        # respond: server_id_len | server_id | server_ed_pub | server_xpub | server_nonce | sig_len | sig
        server_nonce = os.urandom(16)
        server_x_pub_bytes = x25519_serialize_pub(server_x_pub)
        server_ed_pub_bytes = ed25519_serialize_pub(self.pub)
        to_sign = SERVER_ID + server_x_pub_bytes + server_nonce
        signature = self.priv.sign(to_sign)
        resp = bytes([len(SERVER_ID)]) + SERVER_ID + server_ed_pub_bytes + server_x_pub_bytes + server_nonce + len(signature).to_bytes(2, 'big') + signature
        self.sock.sendto(resp, peer)
        print(f"[+] Handshake response sent to {peer} (session established)")

    def send_encrypted(self, peer, payload: bytes, msg_type=MSG_TYPE_DATA, session: ClientSession = None):
        if session is None:
            session = self.sessions.get(peer)
        if session is None or session.session is None:
            print("[-] send_encrypted: no session for", peer)
            return
        ks = session.session
        nonce = ks.nonce_counter.next()
        aad = struct.pack(HEADER_FMT, ks.send_seq, msg_type)
        ct = aesgcm_encrypt(ks.key, nonce, payload, aad)
        pkt = pack_message(ks.send_seq, msg_type, nonce, ct)
        self.sock.sendto(pkt, peer)
        with session.lock:
            ks.send_seq += 1
            ks.bytes_transferred += len(ct)

    def initiate_rekey(self, session: ClientSession, timeout: float = 5.0):
        with session.lock:
            ks = session.session
        if ks is None:
            return
        print(f"[*] Initiating rekey to {session.peer}")
        new_priv, new_pub = generate_x25519_keypair()
        new_pub_bytes = x25519_serialize_pub(new_pub)
        tag = hmac_sha256(ks.key, REKEY_HMAC_INFO + new_pub_bytes)
        plain = new_pub_bytes + tag
        self.send_encrypted(session.peer, plain, msg_type=MSG_TYPE_REKEY_REQ, session=session)
        start = time.time()
        while time.time() - start < timeout:
            time.sleep(0.1)
        print("[*] Rekey initiation wait done (see logs for response)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind-ip", default="0.0.0.0")
    parser.add_argument("--bind-port", type=int, default=5000)
    parser.add_argument("--priv", default="server_ed25519_priv.bin")
    parser.add_argument("--pub", default="server_ed25519_pub.bin")
    parser.add_argument("--generate-keys", action="store_true")
    args = parser.parse_args()

    if args.generate_keys:
        priv, pub = generate_ed25519_keypair()
        save_keypair(priv, args.priv, args.pub)
        print("[*] Generated server ed25519 keypair.")
        exit(0)

    if not os.path.exists(args.priv) or not os.path.exists(args.pub):
        print("[-] Missing key files. Run with --generate-keys first.")
        exit(1)

    priv, pub = load_keypair(args.priv, args.pub)
    server = VPNServer(args.bind_ip, args.bind_port, priv)
    server.start()
