#!/usr/bin/env python3

import socket
import subprocess
import threading
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "honeypot.config")
LOG_FILE = "/var/log/ipdefender/ssh_honeypot.log"
DEFAULT_PORTS = [2222]

def load_ports():
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            f.write("Port=2222\n")
        return DEFAULT_PORTS

    with open(CONFIG_PATH, "r") as f:
        for line in f:
            if line.strip().startswith("Port="):
                port_line = line.strip().split("=", 1)[1]
                try:
                    ports = [int(p.strip()) for p in port_line.split(",") if p.strip().isdigit()]
                    return ports if ports else DEFAULT_PORTS
                except Exception:
                    return DEFAULT_PORTS
    return DEFAULT_PORTS

def log(ip, port):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(f"[HONEYPOT] Port {port} - Connection from {ip}\n")

def handle_connection(client_socket, client_address, port):
    ip = client_address[0]
    log(ip, port)
    print(f"[HONEYPOT] Port {port} - Detected IP: {ip}")
    try:
        fake_banner = b"SSH-2.0-OpenSSH_8.9p1 Debian-1\r\n"
        client_socket.sendall(fake_banner)
    except Exception as e:
        print(f"[ERROR] Failed to send banner to {ip}: {e}")
    try:
        subprocess.run(["IPDefender", "--ban", ip], timeout=15)
    except Exception as e:
        print(f"[ERROR] Ban failed for {ip}: {e}")
    client_socket.close()

def start_honeypot(port):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(5)
        print(f"[HONEYPOT] Listening on port {port}...")
        while True:
            client_socket, addr = server.accept()
            thread = threading.Thread(target=handle_connection, args=(client_socket, addr, port))
            thread.daemon = True
            thread.start()
    except Exception as e:
        print(f"[ERROR] Failed to start on port {port}: {e}")

if __name__ == "__main__":
    ports = load_ports()
    for port in ports:
        threading.Thread(target=start_honeypot, args=(port,), daemon=True).start()

    # Keep main thread alive
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[HONEYPOT] Stopped by user.")
