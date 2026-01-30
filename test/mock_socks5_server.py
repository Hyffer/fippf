# This is a mock SOCKS5 server,
# who also acts as a HTTP server,
# echoing back request details in JSON format.

import os
import socket
import struct
import threading
import json
import time

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data += chunk
    return data

def handle_client(conn, addr):
    try:
        # ======================
        # SOCKS5 handshake
        # ======================
        ver, nmethods = recv_exact(conn, 2)
        methods = recv_exact(conn, nmethods)

        # accept "no authentication"
        conn.sendall(b"\x05\x00")

        # ======================
        # SOCKS5 request
        # ======================
        ver, cmd, rsv, atyp = recv_exact(conn, 4)

        if cmd != 0x01:
            raise ValueError("Only CONNECT supported")

        if atyp == 0x01:  # IPv4
            dst_addr = socket.inet_ntoa(recv_exact(conn, 4))
        elif atyp == 0x03:  # DOMAIN
            length = recv_exact(conn, 1)[0]
            dst_addr = recv_exact(conn, length).decode()
        elif atyp == 0x04:  # IPv6
            dst_addr = socket.inet_ntop(socket.AF_INET6, recv_exact(conn, 16))
        else:
            raise ValueError("Unknown ATYP")

        dst_port = struct.unpack("!H", recv_exact(conn, 2))[0]

        # ======================
        # Reply: connection OK
        # ======================
        reply = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0)
        conn.sendall(reply)

        # ======================
        # Read HTTP request
        # ======================
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk

        request_text = data.decode(errors="replace")
        lines = request_text.split("\r\n")

        request_line = lines[0] if lines else ""
        headers = {}
        for line in lines[1:]:
            if not line:
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        method, path, *_ = request_line.split(" ", 2) if request_line else ("", "", "")

        # ======================
        # Mock HTTP response
        # ======================
        response_body = {
            "client": f"{addr[0]}:{addr[1]}",
            "target_host": dst_addr,
            "target_port": dst_port,
            "http_method": method,
            "http_path": path,
            "headers": headers,
        }

        body = json.dumps(response_body, indent=2).encode()

        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" +
            body
        )

        conn.sendall(http_response)

    except Exception as e:
        print(f"[!] {addr} error:", e)
    finally:
        conn.close()

def main(host, port):
    print(f"SOCKS5 mock HTTP server listening on {host}:{port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


def self_test(host, port):
    threading.Thread(target=main, args=(host, port), daemon=True).start()
    time.sleep(1)

    from test_with_curl import run_test
    result = run_test("--socks5-hostname", f"{host}:{port}")
    if result != 0:
        print("Mock server self-test FAILED")
    else:
        print("Mock server self-test passed")
    os._exit(result)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=str,
                        default="0.0.0.0:1080", help="host:port to listen on")
    parser.add_argument("--self-test",
                        action="store_true", help="run self test")

    args = parser.parse_args()
    host, port_str = args.listen.split(":")
    port = int(port_str)
    if args.self_test:
        self_test(host, port)
    else:
        main(host, port)
