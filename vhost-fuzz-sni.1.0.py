#!/usr/bin/env python3
"""
vhost-fuzz-sni.1.0.py — VHOST fuzzer with SNI = Host header.

Use when the server requires TLS SNI to match the HTTP Host header to respond.
Only run this against infrastructure you own or are explicitly authorised to test.

What's new vs 0.x
-----------------
  * location / redirect_host columns (3xx targets) — the biggest dedup win
  * TLS certificate columns: cert_cn, cert_sans, cert_match, cert_expiry
    cert_match is the strongest "this vhost is real" signal in SNI fuzzing
  * body_hash + fingerprint columns so dedup is one GROUP BY, not a heuristic
  * words / lines counts (catch same-length-different-content pages)
  * content_type, server, tech, resp_ms, baseline_diff columns
  * chunked transfer-encoding is now de-chunked (was inflating body_len)
  * gzip/deflate/br response bodies are decompressed
  * reads Content-Length instead of waiting out the timeout on every request
  * real byte cap on response size (the old --> 64-recv-call cap was not 512KB)
  * --unique-out writes a deduped CSV alongside the raw one
  * --filter-baseline auto-hides anything identical to the IP's baseline
  * -H custom headers, --method, --delay, --retries, --jsonl

Usage
-----
    python3 vhost-fuzz-sni.1.0.py -t 10.0.0.1 -w vhosts.txt -o out.csv
    python3 vhost-fuzz-sni.1.0.py -T targets.txt -w vhosts.txt -o out.csv --unique-out uniq.csv
    python3 vhost-fuzz-sni.1.0.py -t 10.0.0.1 -w vhosts.txt --filter-baseline --threads 20
    python3 vhost-fuzz-sni.1.0.py -t 10.0.0.1 -w vhosts.txt --cert-only   # handshake, no HTTP

Optional dependency: `pip install cryptography` enables the cert_* columns.
Optional dependency: `pip install brotli` enables br-encoded bodies.
"""

import argparse
import base64
import csv
import gzip
import hashlib
import json
import random
import re
import signal
import socket
import ssl
import sys
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ── Optional deps ───────────────────────────────────────────────────────────
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

try:
    import brotli
    HAVE_BROTLI = True
except ImportError:
    HAVE_BROTLI = False

# ── Output schema ───────────────────────────────────────────────────────────
CSV_FIELDS = [
    "ip", "host", "status", "status_text",
    "body_len", "words", "lines",
    "title", "content_type", "server",
    "location", "redirect_host",
    "cert_cn", "cert_match", "cert_sans", "cert_issuer", "cert_expiry",
    "tls_version", "resp_ms", "tech",
    "body_hash", "fingerprint", "baseline_diff", "error",
]

# ── Graceful shutdown ───────────────────────────────────────────────────────
shutdown = False


def sig_handler(sig, frame):
    global shutdown
    shutdown = True
    print("\n[!] Shutting down (finishing in-flight requests)...", file=sys.stderr)


signal.signal(signal.SIGINT, sig_handler)


# ── Body helpers ────────────────────────────────────────────────────────────
def dechunk(data: bytes) -> bytes:
    """Decode Transfer-Encoding: chunked. Returns data untouched if malformed."""
    out = bytearray()
    pos = 0
    while pos < len(data):
        idx = data.find(b"\r\n", pos)
        if idx == -1:
            break
        size_field = data[pos:idx].split(b";")[0].strip()
        if not size_field:
            break
        try:
            size = int(size_field, 16)
        except ValueError:
            return data  # not actually chunked / truncated — keep raw
        if size == 0:
            break
        start = idx + 2
        out += data[start:start + size]
        pos = start + size + 2
    return bytes(out)


def decompress(data: bytes, encoding: str) -> bytes:
    """Decompress a response body. Returns raw data on any failure."""
    enc = (encoding or "").lower().strip()
    try:
        if enc == "gzip" or enc == "x-gzip":
            return gzip.decompress(data)
        if enc == "deflate":
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS)
        if enc == "br" and HAVE_BROTLI:
            return brotli.decompress(data)
    except Exception:
        pass
    return data


# Tokens that change per-request and would otherwise defeat hashing.
_NOISE = [
    (re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), b"UUID"),
    (re.compile(rb"[0-9a-fA-F]{32,64}"), b"HEX"),
    (re.compile(rb"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"), b"TS"),
    (re.compile(rb"\d+"), b"N"),
    (re.compile(rb"\s+"), b" "),
]


def body_fingerprint(body: bytes) -> str:
    """Hash of the body with volatile tokens masked out — stable across reloads."""
    if not body:
        return ""
    norm = body
    for pattern, repl in _NOISE:
        norm = pattern.sub(repl, norm)
    return hashlib.sha1(norm.strip()).hexdigest()[:12]


def count_words_lines(body: str):
    if not body:
        return 0, 0
    return len(body.split()), body.count("\n") + 1


# ── Tech fingerprinting (header-based, deliberately shallow) ─────────────────
_TECH_HEADERS = [
    ("server", "cloudflare", "Cloudflare"),
    ("server", "cloudfront", "CloudFront"),
    ("server", "akamaighost", "Akamai"),
    ("server", "nginx", "nginx"),
    ("server", "apache", "Apache"),
    ("server", "microsoft-iis", "IIS"),
    ("server", "bigip", "F5"),
    ("server", "envoy", "Envoy"),
    ("via", "varnish", "Varnish"),
    ("x-amz-cf-id", "", "CloudFront"),
    ("x-azure-ref", "", "Azure FrontDoor"),
    ("x-akamai-transformed", "", "Akamai"),
    ("cf-ray", "", "Cloudflare"),
    ("x-iinfo", "", "Imperva"),
    ("x-sucuri-id", "", "Sucuri"),
]

_TECH_COOKIES = [
    ("jsessionid", "Java"),
    ("asp.net_sessionid", "ASP.NET"),
    ("phpsessid", "PHP"),
    ("bigipserver", "F5"),
    ("ci_session", "CodeIgniter"),
    ("laravel_session", "Laravel"),
]


def detect_tech(headers: dict) -> str:
    found = []
    for header, needle, label in _TECH_HEADERS:
        val = headers.get(header, "").lower()
        if header in headers and (not needle or needle in val):
            if label not in found:
                found.append(label)
    powered = headers.get("x-powered-by", "")
    if powered and powered not in found:
        found.append(powered[:30])
    cookies = headers.get("set-cookie", "").lower()
    for needle, label in _TECH_COOKIES:
        if needle in cookies and label not in found:
            found.append(label)
    return "|".join(found[:5])


# ── Certificate parsing ─────────────────────────────────────────────────────
def parse_cert(der: bytes, sni_host: str) -> dict:
    """Pull CN / SANs / issuer / expiry out of a DER cert and test SNI match."""
    out = {"cert_cn": "", "cert_sans": "", "cert_match": "", "cert_issuer": "", "cert_expiry": ""}
    if not der or not HAVE_CRYPTO:
        return out
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())

        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        cn = cn_attrs[0].value if cn_attrs else ""
        out["cert_cn"] = cn

        iss_attrs = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        out["cert_issuer"] = iss_attrs[0].value if iss_attrs else ""

        try:
            out["cert_expiry"] = cert.not_valid_after_utc.strftime("%Y-%m-%d")
        except AttributeError:  # cryptography < 42
            out["cert_expiry"] = cert.not_valid_after.strftime("%Y-%m-%d")

        sans = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        out["cert_sans"] = ";".join(sans[:8]) + ("..." if len(sans) > 8 else "")
        names = ([cn] if cn else []) + sans
        out["cert_match"] = "yes" if host_matches(sni_host, names) else "no"
    except Exception as exc:
        out["cert_cn"] = "PARSE_ERR: {}".format(str(exc)[:40])
    return out


def host_matches(host: str, names) -> bool:
    """RFC-ish wildcard match of a hostname against cert names."""
    host = (host or "").lower().rstrip(".")
    for name in names:
        name = (name or "").lower().rstrip(".")
        if not name:
            continue
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]  # ".example.com"
            if host.endswith(suffix) and host.count(".") == name.count("."):
                return True
    return False


# ── HTTP response parsing ───────────────────────────────────────────────────
def parse_response(header_bytes: bytes, body_bytes: bytes) -> dict:
    header_text = header_bytes.decode("iso-8859-1", errors="replace")
    lines = header_text.split("\r\n")

    status, status_text = 0, "PARSE_ERR"
    if lines:
        m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})\s*(.*)", lines[0])
        if m:
            status = int(m.group(1))
            status_text = m.group(2).strip()

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip().lower()
            v = v.strip()
            # Multiple Set-Cookie etc. — join rather than clobber
            headers[k] = (headers[k] + " ; " + v) if k in headers else v

    body = decompress(body_bytes, headers.get("content-encoding", ""))
    body_text = body.decode("utf-8", errors="replace")

    title = ""
    tm = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL)
    if tm:
        title = " ".join(tm.group(1).split())[:120]

    words, line_count = count_words_lines(body_text)
    location = headers.get("location", "")
    redirect_host = ""
    if location:
        try:
            redirect_host = urlparse(location).hostname or ""
        except ValueError:
            redirect_host = ""

    return {
        "status": status,
        "status_text": status_text,
        "headers": headers,
        "body": body_text,
        "body_len": len(body),
        "words": words,
        "lines": line_count,
        "title": title,
        "content_type": headers.get("content-type", "").split(";")[0].strip(),
        "server": headers.get("server", "")[:60],
        "location": location[:300],
        "redirect_host": redirect_host,
        "tech": detect_tech(headers),
        "body_hash": body_fingerprint(body),
    }


def read_full_response(sock, timeout: float, max_bytes: int):
    """Read headers, then use Content-Length / chunked framing to stop early."""
    sock.settimeout(timeout)
    buf = b""

    # 1. headers
    while b"\r\n\r\n" not in buf:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if len(buf) > 131072:  # runaway header block
            break

    split = buf.find(b"\r\n\r\n")
    if split == -1:
        return buf, b""

    header_bytes = buf[:split]
    body = buf[split + 4:]

    lowered = header_bytes.lower()
    content_length = None
    m = re.search(rb"\r\ncontent-length:\s*(\d+)", b"\r\n" + lowered)
    if m:
        content_length = int(m.group(1))
    chunked = b"transfer-encoding:" in lowered and b"chunked" in lowered

    # 2. body
    while True:
        if content_length is not None and len(body) >= content_length:
            break
        if chunked and body.rstrip().endswith(b"0\r\n\r\n".rstrip()):
            break
        if len(body) >= max_bytes:
            break
        try:
            chunk = sock.recv(16384)
        except socket.timeout:
            break
        except ssl.SSLWantReadError:
            continue
        if not chunk:
            break
        body += chunk

    if content_length is not None:
        body = body[:content_length]
    if chunked:
        body = dechunk(body)

    return header_bytes, body


# ── Proxy-aware connection ──────────────────────────────────────────────────
def create_tunneled_connection(ip, port, timeout, proxy_host, proxy_port,
                               proxy_user=None, proxy_pass=None):
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    req = "CONNECT {0}:{1} HTTP/1.1\r\nHost: {0}:{1}\r\n".format(ip, port)
    if proxy_user and proxy_pass:
        creds = base64.b64encode("{}:{}".format(proxy_user, proxy_pass).encode()).decode()
        req += "Proxy-Authorization: Basic {}\r\n".format(creds)
    req += "\r\n"
    sock.sendall(req.encode())

    resp = b""
    sock.settimeout(timeout)
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Proxy closed connection during CONNECT")
        resp += chunk
        if len(resp) > 8192:
            raise ConnectionError("Proxy response too large")

    status_line = resp.split(b"\r\n")[0].decode("utf-8", errors="replace")
    if " 200 " not in status_line:
        raise ConnectionError("Proxy rejected CONNECT: {}".format(status_line.strip()))
    return sock


def create_target_socket(ip, port, timeout, proxy=None):
    if proxy:
        p = urlparse(proxy)
        return create_tunneled_connection(ip, port, timeout, p.hostname,
                                          p.port or 8080, p.username, p.password)
    return socket.create_connection((ip, port), timeout=timeout)


# ── Single vhost probe ──────────────────────────────────────────────────────
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def probe_vhost(host, ip, opts):
    """TLS handshake with SNI=host, then HTTP request with Host: host."""
    result = {f: "" for f in CSV_FIELDS}
    result.update({"host": host, "ip": ip, "status": 0,
                   "status_text": "UNKNOWN", "body_len": 0,
                   "words": 0, "lines": 0, "error": None, "body": ""})

    if shutdown:
        result["error"] = "SHUTDOWN"
        return result

    if opts.delay:
        time.sleep(opts.delay * random.uniform(0.5, 1.5))

    attempts = opts.retries + 1
    for attempt in range(attempts):
        sock = ssl_sock = None
        started = time.time()
        try:
            sock = create_target_socket(ip, opts.port, opts.timeout, opts.proxy)

            # PROTOCOL_TLS_CLIENT — create_default_context() can drop SNI on
            # some Python/macOS builds. server_hostname is what sets SNI.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            ssl_sock = context.wrap_socket(sock, server_hostname=host)

            result["tls_version"] = ssl_sock.version() or ""

            if not opts.no_cert and HAVE_CRYPTO:
                try:
                    result.update(parse_cert(ssl_sock.getpeercert(binary_form=True), host))
                except Exception:
                    pass

            if opts.debug:
                print("    [DEBUG] SNI={} -> {}:{} ({})".format(
                    host, ip, opts.port, result["tls_version"]), file=sys.stderr)

            if opts.cert_only:
                result["resp_ms"] = int((time.time() - started) * 1000)
                result["status_text"] = "TLS_OK"
                return result

            req = "{} {} HTTP/1.1\r\nHost: {}\r\n".format(opts.method, opts.path, host)
            req += "User-Agent: {}\r\n".format(opts.user_agent)
            req += "Accept: */*\r\nAccept-Encoding: gzip, deflate\r\n"
            for h in opts.headers:
                req += h + "\r\n"
            req += "Connection: close\r\n\r\n"
            ssl_sock.sendall(req.encode())

            header_bytes, body_bytes = read_full_response(ssl_sock, opts.timeout, opts.max_body)
            result["resp_ms"] = int((time.time() - started) * 1000)

            if not header_bytes:
                result["error"] = "NO_RESPONSE"
                return result

            parsed = parse_response(header_bytes, body_bytes)
            result.update({k: v for k, v in parsed.items() if k != "headers"})
            result["error"] = None
            return result

        except ssl.SSLError as e:
            result["error"] = "SSL: {}".format(str(e)[:60])
        except socket.timeout:
            result["error"] = "TIMEOUT"
        except ConnectionRefusedError:
            result["error"] = "REFUSED"
            return result  # no point retrying
        except ConnectionError as e:
            result["error"] = "CONN: {}".format(str(e)[:60])
        except OSError as e:
            result["error"] = "OS: {}".format(str(e)[:60])
        except Exception as e:
            result["error"] = "ERR: {}".format(str(e)[:60])
        finally:
            for s in (ssl_sock, sock):
                try:
                    if s:
                        s.close()
                except Exception:
                    pass

        if attempt < attempts - 1 and not shutdown:
            time.sleep(0.3 * (attempt + 1))

    result["resp_ms"] = int((time.time() - started) * 1000)
    return result


def compute_fingerprint(r):
    """What makes two rows 'the same finding'. Dedup keys on this."""
    parts = [
        str(r.get("status", 0)),
        r.get("body_hash", "") or str(r.get("body_len", 0)),
        (r.get("title") or "").lower(),
        r.get("redirect_host", "") or (r.get("location", "") or "")[:80],
        r.get("content_type", ""),
    ]
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]


# ── Main ────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="VHOST fuzzer — TLS SNI matches Host header on every request",
        epilog="Only use against systems you own or are authorised to test.",
    )
    ap.add_argument("-t", "--target", help="Target IP or hostname")
    ap.add_argument("-T", "--target-file", help="File of target IPs/hostnames")
    ap.add_argument("-p", "--port", type=int, default=443, help="Target port (default 443)")
    ap.add_argument("-w", "--wordlist", required=True, help="VHOST wordlist (one per line)")
    ap.add_argument("--path", default="/", help="Request path (default /)")
    ap.add_argument("--method", default="GET", help="HTTP method (default GET; HEAD is faster)")
    ap.add_argument("-H", "--header", action="append", default=[],
                    dest="raw_headers", help="Extra request header, repeatable ('X-Foo: bar')")
    ap.add_argument("--user-agent", default=DEFAULT_UA, help="Override User-Agent")
    ap.add_argument("--threads", type=int, default=10, help="Concurrent threads (default 10)")
    ap.add_argument("--timeout", type=float, default=8.0, help="Timeout seconds (default 8)")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="Per-request delay in seconds, jittered 0.5-1.5x (default 0)")
    ap.add_argument("--retries", type=int, default=0, help="Retries on transient errors (default 0)")
    ap.add_argument("--max-body", type=int, default=524288,
                    help="Max response body bytes to read (default 512KB)")
    ap.add_argument("--filter-code", help="Comma-separated status codes to hide")
    ap.add_argument("--filter-size", type=int, help="Hide responses with this exact body size")
    ap.add_argument("--filter-baseline", action="store_true",
                    help="Hide anything whose fingerprint matches the IP's baseline")
    ap.add_argument("--show-all", action="store_true", help="Show errored probes too")
    ap.add_argument("--no-baseline", action="store_true", help="Skip baseline probe")
    ap.add_argument("--no-cert", action="store_true", help="Skip certificate parsing (faster)")
    ap.add_argument("--cert-only", action="store_true",
                    help="TLS handshake only, no HTTP request — fast cert/SAN harvest")
    ap.add_argument("--proxy", help="Proxy URL (http://[user:pass@]host:port)")
    ap.add_argument("--debug", action="store_true", help="Print SNI values sent")
    ap.add_argument("-o", "--output", help="Write raw results to CSV")
    ap.add_argument("--unique-out", help="Write deduped results to a second CSV")
    ap.add_argument("--jsonl", help="Write results as JSON Lines")
    ap.add_argument("--output-body", action="store_true", help="Include response body in CSV")
    args = ap.parse_args()

    args.headers = []
    for h in args.raw_headers:
        if ":" in h:
            args.headers.append(h.strip())
        else:
            print("[!] Ignoring malformed header: {}".format(h), file=sys.stderr)

    if not args.target and not args.target_file:
        sys.exit("[!] Must specify -t or -T")

    if not HAVE_CRYPTO and not args.no_cert:
        print("[!] `cryptography` not installed — cert_* columns will be empty "
              "(pip install cryptography)", file=sys.stderr)

    # ── Targets ─────────────────────────────────────────────────────────
    targets = []
    if args.target:
        targets.append(args.target)
    if args.target_file:
        try:
            with open(args.target_file) as f:
                targets += [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            sys.exit("[!] Target file not found: {}".format(args.target_file))

    resolved = {}
    for t in targets:
        try:
            ip = socket.gethostbyname(t)
            resolved.setdefault(ip, t)
        except socket.gaierror:
            print("[!] Cannot resolve: {}, skipping".format(t), file=sys.stderr)

    if not resolved:
        sys.exit("[!] No resolvable targets")

    ips = list(resolved.keys())

    try:
        with open(args.wordlist) as f:
            hosts = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        sys.exit("[!] Wordlist not found: {}".format(args.wordlist))

    total_probes = len(ips) * len(hosts)
    print("[*] Targets: {} IP(s)".format(len(ips)))
    for ip in ips:
        print("    {} ({}):{}".format(resolved[ip], ip, args.port))
    if args.proxy:
        print("[*] Proxy: {}".format(args.proxy))
    print("[*] Path: {} | Method: {}".format(args.path, args.method))
    print("[*] Threads: {} | Timeout: {}s | Retries: {}".format(
        args.threads, args.timeout, args.retries))
    print("[*] Loaded {} vhosts — {} total probes\n".format(len(hosts), total_probes))

    filter_codes = set()
    if args.filter_code:
        filter_codes = {int(c) for c in args.filter_code.split(",") if c.strip().isdigit()}

    # ── Baselines ───────────────────────────────────────────────────────
    baselines = {}
    if not args.no_baseline:
        for ip in ips:
            bl = probe_vhost(ip, ip, args)
            bl["fingerprint"] = compute_fingerprint(bl)
            baselines[ip] = bl
            if bl.get("error"):
                print("[*] Baseline {}: ERROR — {}".format(ip, bl["error"]))
            else:
                print("[*] Baseline {}: {} | {}B | {} | {}".format(
                    ip, bl["status"], bl["body_len"],
                    (bl.get("title") or "")[:40], bl.get("location", "")[:40]))
        print()

    # ── Fuzz ────────────────────────────────────────────────────────────
    print("{:>15}  {:>6}  {:>8}  {:<38}  {:<28}  VHOST".format(
        "IP", "STATUS", "SIZE", "TITLE / ERROR", "LOCATION / CERT"))
    print("{}  {}  {}  {}  {}  {}".format(
        "─" * 15, "─" * 6, "─" * 8, "─" * 38, "─" * 28, "─" * 30))

    results = []
    done = 0
    start = time.time()
    work = [(h, ip) for ip in ips for h in hosts]

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(probe_vhost, h, ip, args): (h, ip) for h, ip in work}
        for fut in as_completed(futures):
            if shutdown:
                ex.shutdown(wait=False, cancel_futures=True)
                break
            done += 1
            r = fut.result()
            h, ip = futures[fut]
            r["ip"] = ip
            r["fingerprint"] = compute_fingerprint(r)

            bl = baselines.get(ip)
            if bl and not bl.get("error") and not r.get("error"):
                r["baseline_diff"] = "yes" if r["fingerprint"] != bl["fingerprint"] else "no"
            results.append(r)

            if r.get("error"):
                if args.show_all:
                    print("{:>15}  {:>6}  {:>8}  {:<38.38}  {:<28.28}  {}".format(
                        ip, "ERR", "", r["error"], "", r["host"]))
                continue
            if r["status"] in filter_codes:
                continue
            if args.filter_size is not None and r["body_len"] == args.filter_size:
                continue
            if args.filter_baseline and r.get("baseline_diff") == "no":
                continue

            marker = "★" if r.get("baseline_diff") == "yes" else " "
            note = r.get("location", "")
            if not note and r.get("cert_match") == "yes":
                note = "cert:" + (r.get("cert_cn") or "match")
            desc = r.get("title") or (r.get("body", "")[:38].replace("\n", " "))

            print("{:>15}  {:>5}{}  {:>8}  {:<38.38}  {:<28.28}  {}".format(
                ip, r["status"], marker, r["body_len"], desc, note, r["host"]))

    elapsed = max(time.time() - start, 0.001)
    print("\n[*] Done. {}/{} probes in {:.1f}s ({:.1f} req/s)".format(
        done, total_probes, elapsed, done / elapsed))

    ok = [r for r in results if not r.get("error")]
    errs = [r for r in results if r.get("error")]
    print("[*] {} responded, {} errors".format(len(ok), len(errs)))
    if HAVE_CRYPTO and not args.no_cert:
        matched = [r for r in results if r.get("cert_match") == "yes"]
        print("[*] {} vhosts returned a certificate matching their own SNI".format(len(matched)))
    uniq_fp = {r["fingerprint"] for r in ok}
    print("[*] {} distinct response fingerprints across {} responses".format(len(uniq_fp), len(ok)))

    for ip in ips:
        ip_ok = [r for r in ok if r.get("ip") == ip]
        ip_fp = {r["fingerprint"] for r in ip_ok}
        print("    {}: {} ok, {} distinct".format(ip, len(ip_ok), len(ip_fp)))

    # ── Output ──────────────────────────────────────────────────────────
    def write_csv(path, rows, extra=()):
        fields = CSV_FIELDS + list(extra) + (["body"] if args.output_body else [])
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow({k: ("" if r.get(k) is None else r.get(k, "")) for k in fields})

    if args.output:
        write_csv(args.output, results)
        print("[*] Raw results -> {}".format(args.output))

    if args.unique_out:
        seen = {}
        for r in results:
            if r.get("error"):
                continue
            key = (r["ip"], r["fingerprint"])
            if key not in seen:
                r = dict(r)
                r["dup_count"] = 1
                r["_hosts"] = [r["host"]]
                seen[key] = r
            else:
                seen[key]["dup_count"] += 1
                seen[key]["_hosts"].append(r["host"])
        for r in seen.values():
            hosts = sorted(r.pop("_hosts"), key=lambda h: (len(h), h))
            r["host"] = hosts[0]          # shortest name is usually canonical
            r["also_seen"] = ";".join(hosts[1:11])
            if len(hosts) > 11:
                r["also_seen"] += ";... +{} more".format(len(hosts) - 11)
        write_csv(args.unique_out, list(seen.values()), extra=["dup_count", "also_seen"])
        print("[*] {} unique findings -> {}".format(len(seen), args.unique_out))

    if args.jsonl:
        with open(args.jsonl, "w", encoding="utf-8") as f:
            for r in results:
                row = {k: r.get(k) for k in CSV_FIELDS}
                if args.output_body:
                    row["body"] = r.get("body", "")
                f.write(json.dumps(row, default=str) + "\n")
        print("[*] JSONL -> {}".format(args.jsonl))


if __name__ == "__main__":
    main()
