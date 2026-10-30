#!/usr/bin/env python3
"""Minimal HTTP CONNECT and SOCKS5 proxies for the ShellDrive interop tests (Python 3 stdlib only).

Test infrastructure only (decisions.md D21); nothing of it ships. Started by ../fixture.sh as the WSL user.

  python3 -I proxy.py --mode http|socks5 --listen 127.0.0.1:2280 [--listen 172.x.y.z:2280]
                      [--auth user:pass] [--allow 127.0.0.0/8 ...] [--log file] [--pidfile file]

HTTP: only CONNECT (RFC 9110 9.3.6). With --auth a request without valid "Proxy-Authorization: Basic" gets
407 + Proxy-Authenticate and the client may retry on the same connection. Other methods get 405.
SOCKS5 (RFC 1928): CONNECT only (others get reply 07), ATYP IPv4 / domain / IPv6. With --auth only method 02
(RFC 1929 username/password) is offered; without it only method 00.
Destinations outside --allow (default: loopback and this machine's own addresses) are refused (HTTP 403,
SOCKS reply 02), so the proxy is never an open relay. Each request is logged as one line:
  <iso time> <mode> <client> <dest> <result>
"""
import argparse
import asyncio
import base64
import datetime
import ipaddress
import os
import socket
import struct
import sys

LOG = None
ALLOW = []
AUTH = None


def log(mode, client, dest, result):
    line = "%s %s %s %s %s\n" % (datetime.datetime.now().isoformat(timespec="milliseconds"), mode, client,
                                 dest, result)
    if LOG:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line)
    else:
        sys.stdout.write(line)
        sys.stdout.flush()


def own_addresses():
    nets = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            nets.append(ipaddress.ip_network(info[4][0].split("%")[0]))
    except OSError:
        pass
    try:
        import subprocess
        out = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) > 3 and parts[2] in ("inet", "inet6"):
                nets.append(ipaddress.ip_network(parts[3].split("/")[0]))
    except Exception:
        pass
    return nets


async def resolve_allowed(host, port):
    """Returns (ip, family) or raises PermissionError / OSError."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for fam, _, _, _, sa in infos:
        ip = ipaddress.ip_address(sa[0].split("%")[0])
        if any(ip in n for n in ALLOW):
            return sa[0], fam
    raise PermissionError("destination not allowed")


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError, asyncio.CancelledError):
        pass
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except (OSError, RuntimeError):
            pass


async def splice(cr, cw, dr, dw):
    await asyncio.gather(pipe(cr, dw), pipe(dr, cw))
    for w in (cw, dw):
        try:
            w.close()
        except OSError:
            pass


def peer(writer):
    p = writer.get_extra_info("peername")
    return "%s:%s" % (p[0], p[1]) if p else "?"


# ---------------------------------------------------------------- HTTP CONNECT
async def http_client(reader, writer):
    client = peer(writer)
    try:
        for _ in range(8):                      # a few requests per connection (407 then retry)
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
                return
            lines = head.decode("latin-1").split("\r\n")
            parts = lines[0].split(" ")
            hdrs = {}
            for l in lines[1:]:
                if ":" in l:
                    k, v = l.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()
            if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                log("http", client, "-", "400")
                return
            method, target = parts[0], parts[1]
            if method != "CONNECT":
                writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Length: 0\r\n"
                             b"Connection: close\r\n\r\n")
                log("http", client, target, "405")
                return
            if AUTH is not None:
                got = hdrs.get("proxy-authorization", "")
                ok = False
                if got[:6].lower() == "basic ":
                    try:
                        ok = base64.b64decode(got[6:].strip(), validate=True).decode("utf-8") == AUTH
                    except (ValueError, UnicodeDecodeError):
                        ok = False
                if not ok:
                    writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                                 b"Proxy-Authenticate: Basic realm=\"shelldrive-test\"\r\n"
                                 b"Content-Length: 0\r\n\r\n")
                    await writer.drain()
                    log("http", client, target, "407" + (" bad-credentials" if got else ""))
                    continue
            host, _, port = target.rpartition(":")
            host = host.strip("[]")
            try:
                port = int(port)
                ip, _ = await resolve_allowed(host, port)
                dr, dw = await asyncio.wait_for(asyncio.open_connection(ip, port), 15)
            except PermissionError:
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                log("http", client, target, "403")
                return
            except (OSError, ValueError, asyncio.TimeoutError) as e:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                log("http", client, target, "502 " + type(e).__name__)
                return
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            log("http", client, target, "200")
            await splice(reader, writer, dr, dw)
            return
    finally:
        try:
            writer.close()
        except OSError:
            pass


# ---------------------------------------------------------------- SOCKS5
def socks_reply(code, bind=("0.0.0.0", 0)):
    try:
        ip = ipaddress.ip_address(bind[0])
    except ValueError:
        ip = ipaddress.ip_address("0.0.0.0")
    atyp = 1 if ip.version == 4 else 4
    return bytes([5, code, 0, atyp]) + ip.packed + struct.pack(">H", bind[1])


async def socks_client(reader, writer):
    client = peer(writer)
    dest = "-"
    try:
        ver, n = await reader.readexactly(2)
        if ver != 5:
            log("socks5", client, dest, "bad-version")
            return
        methods = await reader.readexactly(n)
        want = 2 if AUTH is not None else 0
        if want not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            log("socks5", client, dest, "no-acceptable-method")
            return
        writer.write(bytes([5, want]))
        await writer.drain()
        if want == 2:
            sub = await reader.readexactly(2)
            uname = await reader.readexactly(sub[1])
            plen = await reader.readexactly(1)
            passwd = await reader.readexactly(plen[0])
            ok = sub[0] == 1 and (uname + b":" + passwd).decode("utf-8", "replace") == AUTH
            writer.write(bytes([1, 0 if ok else 1]))
            await writer.drain()
            if not ok:
                log("socks5", client, dest, "auth-failed")
                return
        ver, cmd, _, atyp = await reader.readexactly(4)
        if atyp == 1:
            host = str(ipaddress.ip_address(await reader.readexactly(4)))
        elif atyp == 3:
            ln = await reader.readexactly(1)
            host = (await reader.readexactly(ln[0])).decode("idna")
        elif atyp == 4:
            host = str(ipaddress.ip_address(await reader.readexactly(16)))
        else:
            writer.write(socks_reply(8))
            log("socks5", client, dest, "08 atyp")
            return
        (port,) = struct.unpack(">H", await reader.readexactly(2))
        dest = "%s:%d" % (host if ":" not in host else "[%s]" % host, port)
        if cmd != 1:
            writer.write(socks_reply(7))
            log("socks5", client, dest, "07 cmd=%d" % cmd)
            return
        try:
            ip, _ = await resolve_allowed(host, port)
            dr, dw = await asyncio.wait_for(asyncio.open_connection(ip, port), 15)
        except PermissionError:
            writer.write(socks_reply(2))
            log("socks5", client, dest, "02 not-allowed")
            return
        except ConnectionRefusedError:
            writer.write(socks_reply(5))
            log("socks5", client, dest, "05 refused")
            return
        except (OSError, asyncio.TimeoutError) as e:
            writer.write(socks_reply(4))
            log("socks5", client, dest, "04 " + type(e).__name__)
            return
        writer.write(socks_reply(0, dw.get_extra_info("sockname")[:2]))
        await writer.drain()
        log("socks5", client, dest, "00")
        await splice(reader, writer, dr, dw)
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        log("socks5", client, dest, "client-eof")
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def main_async(args):
    handler = http_client if args.mode == "http" else socks_client
    servers = []
    for l in args.listen:
        host, _, port = l.rpartition(":")
        servers.append(await asyncio.start_server(handler, host.strip("[]"), int(port), reuse_address=True))
    if args.pidfile:
        with open(args.pidfile, "w") as f:
            f.write("%d\n" % os.getpid())
    log(args.mode, "-", ",".join(args.listen), "listening auth=%s" % ("yes" if AUTH else "no"))
    await asyncio.gather(*(s.serve_forever() for s in servers))


def main():
    global LOG, ALLOW, AUTH
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("http", "socks5"), required=True)
    ap.add_argument("--listen", action="append", required=True)
    ap.add_argument("--auth")
    ap.add_argument("--allow", action="append")
    ap.add_argument("--log")
    ap.add_argument("--pidfile")
    args = ap.parse_args()
    LOG, AUTH = args.log, args.auth
    ALLOW = [ipaddress.ip_network(a, strict=False) for a in args.allow] if args.allow else own_addresses()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
