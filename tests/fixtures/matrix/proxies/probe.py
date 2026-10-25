#!/usr/bin/env python3
"""Client side of the test proxies, for the fixture self-test (Python 3 stdlib only; test infrastructure).

  python3 -I probe.py http|socks5 <proxy host:port> <dest host> <dest port> [user:pass]
      Relay mode (usable as an OpenSSH ProxyCommand): handshake, then copy stdin -> proxy -> stdout.
      Exit 1 with the proxy's answer on stderr when the proxy refuses.
  python3 -I probe.py --status http|socks5 ...
      Handshake only; print the proxy's status ("200", "407", "00", "02", "auth-failed", ...) and exit 0.
"""
import base64
import socket
import struct
import sys
import threading


def handshake(mode, proxy, host, port, cred):
    ph, _, pp = proxy.rpartition(":")
    s = socket.create_connection((ph, int(pp)), timeout=15)
    if mode == "http":
        req = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (host, port, host, port)
        if cred:
            req += "Proxy-Authorization: Basic %s\r\n" % base64.b64encode(cred.encode()).decode()
        s.sendall((req + "\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d:
                return s, "eof"
            buf += d
        status = buf.split(b" ", 2)[1].decode()
        return s, status
    methods = b"\x02" if cred else b"\x00"
    s.sendall(b"\x05\x01" + methods)
    r = s.recv(2)
    if len(r) < 2 or r[1] == 0xFF:
        return s, "no-method"
    if r[1] == 2:
        u, _, p = cred.partition(":")
        s.sendall(bytes([1, len(u)]) + u.encode() + bytes([len(p)]) + p.encode())
        a = s.recv(2)
        if len(a) < 2 or a[1] != 0:
            return s, "auth-failed"
    try:
        ip = socket.inet_aton(host)
        s.sendall(b"\x05\x01\x00\x01" + ip + struct.pack(">H", port))
    except OSError:
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + struct.pack(">H", port))
    rep = s.recv(4)
    if len(rep) < 4:
        return s, "eof"
    rest = {1: 4, 4: 16}.get(rep[3], 0) + 2
    while rest > 0:
        d = s.recv(rest)
        if not d:
            break
        rest -= len(d)
    return s, "%02d" % rep[1]


def relay(s):
    s.settimeout(None)

    def up():
        try:
            while True:
                d = sys.stdin.buffer.read1(65536)
                if not d:
                    break
                s.sendall(d)
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    threading.Thread(target=up, daemon=True).start()
    while True:
        d = s.recv(65536)
        if not d:
            break
        sys.stdout.buffer.write(d)
        sys.stdout.buffer.flush()


def main(argv):
    status_only = False
    if argv[1:2] == ["--status"]:
        status_only, argv = True, argv[:1] + argv[2:]
    if len(argv) < 5:
        print(__doc__, file=sys.stderr)
        return 2
    mode, proxy, host, port = argv[1], argv[2], argv[3], int(argv[4])
    cred = argv[5] if len(argv) > 5 else ""
    s, st = handshake(mode, proxy, host, port, cred)
    if status_only:
        print(st)
        return 0
    if st not in ("200", "00"):
        print("proxy refused: %s" % st, file=sys.stderr)
        return 1
    relay(s)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
