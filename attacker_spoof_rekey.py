# attacker_spoof_rekey.py
import socket, os
from vpn_common import *

TARGET = ("127.0.0.1", 5000)

def send_fake_rekey():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fake_new_xpub = os.urandom(32)
    fake_hmac = os.urandom(32)
    plain = fake_new_xpub + fake_hmac
    # we must craft an encrypted-like packet structure; the server expects encrypted packet form,
    # but attacker will just send the rekey payload as ciphertext (it will fail to decrypt).
    # Better: send it as if from a valid session by reusing the format header|nonce|ciphertext
    # We'll send a malformed packet to provoke HMAC invalid message on server side.
    seq = 0
    msg_type = MSG_TYPE_REKEY_REQ
    nonce = (0).to_bytes(12, 'big')
    pkt = struct.pack(HEADER_FMT, seq, msg_type) + nonce + plain
    print("[*] Sending fake rekey (spoof) to", TARGET)
    s.sendto(pkt, TARGET)
    s.close()

if __name__ == "__main__":
    send_fake_rekey()
