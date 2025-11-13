# attacker_tamper.py
import socket
import sys
from vpn_common import *

TARGET = ("127.0.0.1", 5000)

def tamper_example():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # craft a fake "encrypted" packet by making random bytes in ciphertext portion
    seq = 0
    msg_type = MSG_TYPE_DATA
    nonce = (0).to_bytes(12, 'big')
    fake_cipher = b"\x00" * 16  # invalid tag/cipher to trigger decryption failure
    pkt = struct.pack(HEADER_FMT, seq, msg_type) + nonce + fake_cipher
    print("[*] Sending tampered packet to", TARGET)
    s.sendto(pkt, TARGET)
    s.close()

if __name__ == "__main__":
    tamper_example()
