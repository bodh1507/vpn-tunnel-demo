# mitm_proxy.py
import socket
import threading
import argparse

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 6000  # client connects here instead of server
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

def forward(a_sock, b_addr, name="to_server"):
    while True:
        data, peer = a_sock.recvfrom(65535)
        print(f"[MITM] {name} saw {len(data)} bytes from {peer}")
        # optional: dump first 80 bytes hex
        print(data[:80].hex())
        a_sock.sendto(data, b_addr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-port", type=int, default=6000)
    parser.add_argument("--server-ip", default=SERVER_IP)
    parser.add_argument("--server-port", type=int, default=SERVER_PORT)
    args = parser.parse_args()
    LISTEN_PORT = args.listen_port
    SERVER_ADDR = (args.server_ip, args.server_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[MITM] Listening on {LISTEN_IP}:{LISTEN_PORT}, forwarding to {SERVER_ADDR}")

    while True:
        data, peer = sock.recvfrom(65535)
        print(f"[MITM] Packet {len(data)} bytes from {peer} -> forward to server")
        print(data[:80].hex())
        # forward to server
        sock.sendto(data, SERVER_ADDR)
