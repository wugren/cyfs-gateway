#!/usr/bin/env python3
import contextlib
import gzip
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote


REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_DIR = REPO_ROOT / "src"
BIN_PATH = SRC_DIR / "target" / "debug" / "cyfs_gateway"
BUILTIN_CONTROL_PORT = 13451
ACTIVE_CONTROL_PORT = None
YAML_CONTROL_PORT_RE = re.compile(r"(?m)^control_port:\s*(\d+)\s*$")
TOML_CONTROL_PORT_RE = re.compile(r"(?m)^control_port\s*=\s*(\d+)\s*$")


class TestFailure(Exception):
    pass


def fail(message):
    raise TestFailure(message)


def assert_eq(actual, expected, message):
    if actual != expected:
        fail(f"{message}: expected {expected!r}, got {actual!r}")


def assert_in(needle, haystack, message):
    if needle not in haystack:
        fail(f"{message}: missing {needle!r} in {haystack!r}")


def assert_not_in(needle, haystack, message):
    if needle in haystack:
        fail(f"{message}: unexpected {needle!r} in {haystack!r}")


def assert_endswith(value, suffix, message):
    if not value.endswith(suffix):
        fail(f"{message}: expected suffix {suffix!r}, got {value!r}")


def assert_true(value, message):
    if not value:
        fail(message)


def assert_process_ok(result, message):
    if result.returncode != 0:
        fail(f"{message}: expected 0, got {result.returncode}\n{result.stdout}")


def free_port():
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def free_udp_port():
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def effective_control_port(port):
    if port == BUILTIN_CONTROL_PORT and ACTIVE_CONTROL_PORT is not None:
        return ACTIVE_CONTROL_PORT
    return port


def build_gateway():
    if os.environ.get("CYFS_GATEWAY_APP_SKIP_BUILD") == "1":
        print("[cyfs-gateway-app] skipping cargo build via CYFS_GATEWAY_APP_SKIP_BUILD=1")
        if not BIN_PATH.exists():
            fail(f"missing built binary: {BIN_PATH}")
        return

    print("[cyfs-gateway-app] building cyfs_gateway")
    result = subprocess.run(
        ["cargo", "build", "-p", "cyfs_gateway"],
        cwd=SRC_DIR,
        text=True,
        timeout=1800,
        check=False,
    )
    if result.returncode != 0:
        fail("cargo build -p cyfs_gateway failed")
    if not BIN_PATH.exists():
        fail(f"missing built binary: {BIN_PATH}")


class GatewayProcess:
    def __init__(
        self,
        case_dir,
        config_path,
        buckyos_root,
        control_port=None,
        extra_args=None,
        extra_env=None,
    ):
        self.case_dir = Path(case_dir)
        self.config_path = Path(config_path)
        self.buckyos_root = Path(buckyos_root)
        self.control_port = control_port or free_port()
        self.extra_args = list(extra_args or [])
        self.extra_env = dict(extra_env or {})
        self.stdout_path = self.case_dir / "gateway.stdout.log"
        self.stderr_path = self.case_dir / "gateway.stderr.log"
        self._stdout = None
        self._stderr = None
        self.proc = None

    def start(self):
        self._ensure_config_control_port()
        self._stdout = self.stdout_path.open("w", encoding="utf-8")
        self._stderr = self.stderr_path.open("w", encoding="utf-8")
        env = os.environ.copy()
        env["BUCKYOS_ROOT"] = str(self.buckyos_root)
        env.update(self.extra_env)
        self.proc = subprocess.Popen(
            [str(BIN_PATH), "--config_file", str(self.config_path), *self.extra_args],
            cwd=self.case_dir,
            env=env,
            stdout=self._stdout,
            stderr=self._stderr,
            text=True,
        )
        global ACTIVE_CONTROL_PORT
        ACTIVE_CONTROL_PORT = self.control_port

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        global ACTIVE_CONTROL_PORT
        if ACTIVE_CONTROL_PORT == self.control_port:
            ACTIVE_CONTROL_PORT = None
        if self._stdout is not None:
            self._stdout.close()
        if self._stderr is not None:
            self._stderr.close()

    def output(self):
        stdout = self.stdout_path.read_text(encoding="utf-8", errors="replace")
        stderr = self.stderr_path.read_text(encoding="utf-8", errors="replace")
        return stdout + "\n" + stderr

    def _ensure_config_control_port(self):
        suffix = self.config_path.suffix.lower()
        if suffix == ".json":
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
            if "control_port" in data:
                self.control_port = int(data["control_port"])
                return
            data["control_port"] = self.control_port
            write_file(self.config_path, json.dumps(data))
            return

        text = self.config_path.read_text(encoding="utf-8")
        if suffix == ".toml":
            match = TOML_CONTROL_PORT_RE.search(text)
            if match:
                self.control_port = int(match.group(1))
                return
            write_file(self.config_path, f"control_port = {self.control_port}\n{text}")
            return

        match = YAML_CONTROL_PORT_RE.search(text)
        if match:
            self.control_port = int(match.group(1))
            return
        write_file(self.config_path, f"control_port: {self.control_port}\n{text}")


class UpstreamServer:
    def __init__(self):
        self.requests = []
        self.httpd = None
        self.thread = None
        self.port = None

    def start(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append(
                    {
                        "method": "GET",
                        "path": self.path,
                        "headers": dict(self.headers.items()),
                    }
                )
                body = f"upstream:{self.path}".encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "text/plain")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)


class BnsRpcServer:
    def __init__(self):
        self.httpd = None
        self.thread = None
        self.port = None

    def start(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", "0"))
                request = json.loads(self.rfile.read(length).decode("utf-8"))
                if self.path != "/kapi/bns" or request.get("method") != "system.info":
                    self.send_error(404)
                    return
                sys_values = request.get("sys") or [0]
                body = json.dumps(
                    {
                        "result": {
                            "ok": True,
                            "result": {
                                "ready": True,
                                "chain_id": 31337,
                                "contract_address": "0x2222222222222222222222222222222222222222",
                            },
                            "error": None,
                        },
                        "sys": [sys_values[0]],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)


class EchoServer:
    def __init__(self):
        self.port = None
        self._sock = None
        self._thread = None
        self._stop = threading.Event()

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)

    def stop(self):
        self._stop.set()
        if self._sock is not None:
            self._sock.close()
        if self._thread is not None:
            self._thread.join(timeout=5)


class UdpEchoServer:
    def __init__(self, prefix=b""):
        self.prefix = prefix
        self.port = None
        self._sock = None
        self._thread = None
        self._stop = threading.Event()

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            self._sock.sendto(self.prefix + data, addr)

    def stop(self):
        self._stop.set()
        if self._sock is not None:
            self._sock.close()
        if self._thread is not None:
            self._thread.join(timeout=5)


def http_request(port, host, path, headers=None, method="GET"):
    headers = dict(headers or {})
    headers.setdefault("Host", host)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, body
    finally:
        conn.close()


def http_text(port, host, path, headers=None, method="GET"):
    status, resp_headers, body = http_request(port, host, path, headers=headers, method=method)
    return status, resp_headers, body.decode("utf-8", errors="replace")


def http_json_rpc(port, host, path, method, params=None, token=None):
    seq = int(time.time() * 1000)
    sys_values = [seq] if token is None else [seq, token]
    payload = json.dumps(
        {"method": method, "params": params if params is not None else {}, "sys": sys_values}
    ).encode("utf-8")
    headers = {
        "Host": host,
        "content-type": "application/json",
        "content-length": str(len(payload)),
    }
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("POST", path, body=payload, headers=headers)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        if resp.status != 200:
            fail(f"http json rpc {method} status: expected 200, got {resp.status}: {body}")
        data = json.loads(body)
        if data.get("error") is not None:
            fail(f"http json rpc {method} error: {data['error']}")
        return data
    finally:
        conn.close()


def raw_http_get_with_bound_source(port, host, path="/"):
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        source_port = sock.getsockname()[1]
        sock.settimeout(5)
        sock.connect(("127.0.0.1", port))
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        sock.sendall(req)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    raw = b"".join(chunks)
    header_bytes, _, body = raw.partition(b"\r\n\r\n")
    header_text = header_bytes.decode("iso-8859-1", errors="replace")
    lines = header_text.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        fail(f"invalid raw http response: {raw!r}")
    parts = lines[0].split(" ", 2)
    status = int(parts[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.lower()] = v.strip()
    return source_port, status, headers, body.decode("utf-8", errors="replace")


def control_get_system_info(port):
    port = effective_control_port(port)
    payload = json.dumps({"method": "get_system_info", "params": {}, "sys": [1]}).encode("utf-8")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        conn.request(
            "POST",
            "/",
            body=payload,
            headers={"content-type": "application/json", "content-length": str(len(payload))},
        )
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        if resp.status != 200:
            return None
        return json.loads(body)
    finally:
        conn.close()


def control_rpc(port, method, params=None, token=None):
    port = effective_control_port(port)
    seq = int(time.time() * 1000)
    sys_values = [seq] if token is None else [seq, token]
    payload = json.dumps(
        {"method": method, "params": params if params is not None else None, "sys": sys_values}
    ).encode("utf-8")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(
            "POST",
            "/",
            body=payload,
            headers={"content-type": "application/json", "content-length": str(len(payload))},
        )
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        if resp.status != 200:
            fail(f"control rpc {method} http status: expected 200, got {resp.status}: {body}")
        data = json.loads(body)
        if data.get("error") is not None:
            fail(f"control rpc {method} error: {data['error']}")
        return data
    finally:
        conn.close()


def control_rpc_raw(port, method, params=None, token=None):
    port = effective_control_port(port)
    seq = int(time.time() * 1000)
    sys_values = [seq] if token is None else [seq, token]
    payload = json.dumps(
        {"method": method, "params": params if params is not None else None, "sys": sys_values}
    ).encode("utf-8")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(
            "POST",
            "/",
            body=payload,
            headers={"content-type": "application/json", "content-length": str(len(payload))},
        )
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(body) if body else None
        except json.JSONDecodeError:
            data = None
        return {"status": resp.status, "body": body, "data": data}
    finally:
        conn.close()


def control_login(port, user_name="app_user", password="app_pass"):
    timestamp = int(time.time())
    digest = hashlib.sha256(f"{user_name}_{password}_{timestamp}".encode("utf-8")).hexdigest()
    resp = control_rpc(
        port,
        "login",
        {"user_name": user_name, "password": digest, "timestamp": timestamp},
    )
    token = resp.get("result")
    if not token:
        fail(f"control login missing token: {resp}")
    return token


def control_reload(port, token):
    return control_rpc(port, "reload", None, token=token)


def run_cli(args, case_dir, buckyos_root=None, timeout=15):
    env = os.environ.copy()
    if buckyos_root is not None:
        env["BUCKYOS_ROOT"] = str(buckyos_root)
    return subprocess.run(
        [str(BIN_PATH), *args],
        cwd=case_dir,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def dns_query(port, name, qtype=1, timeout=5):
    tid = 0x1234
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\0"
    question = qname + struct.pack("!HH", qtype, 1)
    packet = header + question
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
    resp_tid, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    assert_eq(resp_tid, tid, "dns transaction id")
    offset = 12 + len(qname) + 4
    records = []
    for _ in range(an):
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while data[offset] != 0:
                offset += 1 + data[offset]
            offset += 1
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        offset += rdlen
        if rtype == 1 and rclass == 1 and rdlen == 4:
            records.append(("A", socket.inet_ntoa(rdata)))
        elif rtype == 28 and rclass == 1 and rdlen == 16:
            records.append(("AAAA", socket.inet_ntop(socket.AF_INET6, rdata)))
        else:
            records.append((rtype, rdata))
    return {"rcode": flags & 0x000F, "records": records}


def dns_query_a(port, name, timeout=5):
    result = dns_query(port, name, 1, timeout)
    addresses = []
    for rtype, value in result["records"]:
        if rtype == "A":
            addresses.append(value)
    return addresses


def udp_roundtrip(port, payload, timeout=5):
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
        return data


def tcp_roundtrip(port, payload, timeout=5):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(payload)
        return sock.recv(4096)


def assert_tcp_connect_fails(port, message, timeout=1):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            pass
    except OSError:
        return
    fail(message)


def socks5_connect(socks_port, username, password, target_port):
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=5)
    try:
        sock.sendall(bytes([5, 2, 0, 2]))
        method = sock.recv(2)
        if method != bytes([5, 2]):
            fail(f"socks auth method failed: {method!r}")
        user = username.encode("utf-8")
        pw = password.encode("utf-8")
        sock.sendall(bytes([1, len(user)]) + user + bytes([len(pw)]) + pw)
        auth = sock.recv(2)
        if auth != bytes([1, 0]):
            fail(f"socks auth failed: {auth!r}")
        sock.sendall(bytes([5, 1, 0, 1, 127, 0, 0, 1]) + struct.pack("!H", target_port))
        head = sock.recv(4)
        if len(head) != 4 or head[0] != 5:
            fail(f"invalid socks reply: {head!r}")
        atyp = head[3]
        if atyp == 1:
            rest_len = 6
        elif atyp == 3:
            domain_len = sock.recv(1)[0]
            rest_len = domain_len + 2
        elif atyp == 4:
            rest_len = 18
        else:
            fail(f"invalid socks atyp: {atyp}")
        rest = sock.recv(rest_len)
        if len(rest) != rest_len:
            fail("truncated socks reply")
        if head[1] != 0:
            raise OSError(f"socks connect failed: {head[1]}")
        return sock
    except Exception:
        sock.close()
        raise


def socks5_connect_domain(socks_port, username, password, host, target_port):
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=5)
    try:
        sock.sendall(bytes([5, 2, 0, 2]))
        method = sock.recv(2)
        if method != bytes([5, 2]):
            fail(f"socks domain auth method failed: {method!r}")
        user = username.encode("utf-8")
        pw = password.encode("utf-8")
        sock.sendall(bytes([1, len(user)]) + user + bytes([len(pw)]) + pw)
        auth = sock.recv(2)
        if auth != bytes([1, 0]):
            fail(f"socks domain auth failed: {auth!r}")
        host_bytes = host.encode("ascii")
        sock.sendall(bytes([5, 1, 0, 3, len(host_bytes)]) + host_bytes + struct.pack("!H", target_port))
        head = sock.recv(4)
        if len(head) != 4 or head[0] != 5:
            fail(f"invalid socks domain reply: {head!r}")
        if head[3] == 1:
            rest_len = 6
        elif head[3] == 3:
            rest_len = sock.recv(1)[0] + 2
        elif head[3] == 4:
            rest_len = 18
        else:
            fail(f"invalid socks domain atyp: {head[3]}")
        rest = sock.recv(rest_len)
        if len(rest) != rest_len:
            fail("truncated socks domain reply")
        if head[1] != 0:
            raise OSError(f"socks domain connect failed: {head[1]}")
        return sock
    except Exception:
        sock.close()
        raise


def assert_socks_auth_fails(socks_port, username, password):
    with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(bytes([5, 2, 0, 2]))
        method = sock.recv(2)
        assert_eq(method, bytes([5, 2]), "socks wrong-auth method")
        user = username.encode("utf-8")
        pw = password.encode("utf-8")
        sock.sendall(bytes([1, len(user)]) + user + bytes([len(pw)]) + pw)
        auth = sock.recv(2)
        assert_true(auth != bytes([1, 0]), "socks wrong auth should fail")


def wait_gateway_ready(gateway, control_port, timeout_sec=15):
    deadline = time.monotonic() + timeout_sec
    last_error = None
    while time.monotonic() < deadline:
        if gateway.proc.poll() is not None:
            fail(
                "gateway exited before ready; "
                f"code={gateway.proc.returncode}\n{gateway.output()}"
            )
        try:
            resp = control_get_system_info(control_port)
            if resp and resp.get("result") is not None:
                return
        except Exception as exc:
            last_error = exc
        time.sleep(0.1)
    fail(f"gateway did not become ready: {last_error}\n{gateway.output()}")


def wait_tcp_port(gateway, port, name, timeout_sec=15):
    deadline = time.monotonic() + timeout_sec
    last_error = None
    while time.monotonic() < deadline:
        if gateway.proc.poll() is not None:
            fail(
                f"gateway exited before {name} port was ready; "
                f"code={gateway.proc.returncode}\n{gateway.output()}"
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError as exc:
            last_error = exc
        time.sleep(0.1)
    fail(f"{name} port {port} did not become ready: {last_error}\n{gateway.output()}")


def wait_process_output_contains(gateway, needle, message, timeout_sec=5):
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if gateway.proc.poll() is not None:
            fail(
                f"gateway exited before {message}; "
                f"code={gateway.proc.returncode}\n{gateway.output()}"
            )
        output = gateway.output()
        if needle in output:
            return
        time.sleep(0.1)
    fail(f"{message}: missing {needle!r}\n{gateway.output()}")


def print_process_output_matches(gateway, label, needles):
    print(f"[cyfs-gateway-app] {label} logs:")
    matched = False
    seen = set()
    for line in gateway.output().splitlines():
        if any(needle in line for needle in needles) and line not in seen:
            print(f"[cyfs-gateway-app]   {line}")
            seen.add(line)
            matched = True
    if not matched:
        print("[cyfs-gateway-app]   <no matching log lines>")


def write_file(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def install_control_test_template(buckyos_root):
    template_dir = Path(buckyos_root) / "etc" / "cyfs_gateway" / "server_templates" / "control_test"
    write_file(
        template_dir / "pkg.yaml",
        """
name: control_test
description: Control API test template
main: main.js
""".strip()
        + "\n",
    )
    write_file(
        template_dir / "main.js",
        """
export function main(argv) {
    const helpText = [
        "Usage:",
        "  control_test --bind <ip:port> --path <dir>",
    ].join("\\n");
    if (argv.includes("--help") || argv.includes("-h")) {
        console.log(helpText);
        return "";
    }

    let bind = "";
    let rootPath = "";
    for (let i = 0; i < argv.length; i += 1) {
        if (argv[i] === "--bind" && i + 1 < argv.length) {
            bind = String(argv[i + 1]);
            i += 1;
            continue;
        }
        if (argv[i] === "--path" && i + 1 < argv.length) {
            rootPath = String(argv[i + 1]);
            i += 1;
        }
    }
    if (bind.length === 0 || rootPath.length === 0) {
        console.log(helpText);
        return "";
    }

    return JSON.stringify({
        stacks: {
            control_test_stack: {
                bind,
                protocol: "tcp",
                hook_point: {
                    main: {
                        priority: 1,
                        blocks: {
                            default: {
                                priority: 1,
                                block: "call-server control_test_dir;\\n",
                            },
                        },
                    },
                },
            },
        },
        servers: {
            control_test_dir: {
                type: "dir",
                root_path: rootPath,
            },
        },
    });
}
""".strip()
        + "\n",
    )


def render_runtime_config(case_dir, entry_port, upstream_port):
    dir_root = case_dir / "www" / "dir"
    fallback_root = case_dir / "www" / "fallback"
    if_root = case_dir / "www" / "if_dir"
    write_file(dir_root / "index.html", "DIR")
    write_file(fallback_root / "index.html", "FALLBACK")
    write_file(fallback_root / "fallback", "FALLBACK")
    write_file(if_root / "index.html", "IF_DIR")
    write_file(if_root / "if" / "dir", "IF_DIR")

    config = f"""
stacks:
  entry:
    bind: 127.0.0.1:{entry_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;

servers:
  acme_response:
    type: acme_response

  dir.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server dir_case;

  pc.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              if starts-with ${{REQ.path}} "/if/dir" then
                  call-server if_dir;
              elif starts-with ${{REQ.path}} "/if/forward" then
                  forward "http://127.0.0.1:{upstream_port}";
              elif starts-with ${{REQ.path}} "/if/reject" then
                  reject;
              elif starts-with ${{REQ.path}} "/rewrite/" then
                  rewrite ${{REQ.path}} "/rewrite/*" "/*" && forward "http://127.0.0.1:{upstream_port}";
              elif starts-with ${{REQ.path}} "/return-forward" then
                  return "forward http://127.0.0.1:{upstream_port}";
              else
                  call-server fallback_dir;
              end
    post_hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              map-add RESP x-pc-case runtime;

  dir_case:
    type: dir
    root_path: {dir_root}

  fallback_dir:
    type: dir
    root_path: {fallback_root}

  if_dir:
    type: dir
    root_path: {if_root}
"""
    config_path = case_dir / "cyfs_gateway.yaml"
    write_file(config_path, textwrap.dedent(config).strip() + "\n")
    return config_path


def render_full_runtime_config(
    case_dir,
    ports,
    upstream_port,
    echo_direct_port,
    echo_proxy_port,
    variant="initial",
    dns_address="192.168.1.1",
    include_reload_server=False,
):
    if variant == "initial":
        bodies = {
            "dir": "DIR",
            "fallback": "FALLBACK",
            "if_dir": "IF_DIR",
            "shared": "SHARED",
            "for_dir": "FOR_DIR",
            "mr_ok": "MR_OK",
            "nested": "NESTED",
            "gzip": "gzip-body-" * 20,
        }
    else:
        bodies = {
            "dir": "DIR_RELOADED",
            "fallback": "FALLBACK_RELOADED",
            "if_dir": "IF_DIR_RELOADED",
            "shared": "SHARED_RELOADED",
            "for_dir": "FOR_DIR_RELOADED",
            "mr_ok": "MR_OK_RELOADED",
            "nested": "NESTED_RELOADED",
            "gzip": "gzip-reloaded-body-" * 20,
        }

    roots = {}
    for name, body in bodies.items():
        root = case_dir / "www" / variant / name
        roots[name] = root
        write_file(root / "index.html", body)

    write_file(roots["fallback"] / "fallback", bodies["fallback"])
    write_file(roots["fallback"] / "mr" / "miss", bodies["fallback"])
    write_file(roots["if_dir"] / "if" / "dir", bodies["if_dir"])
    write_file(roots["shared"] / "shared", bodies["shared"])
    write_file(roots["for_dir"] / "for" / "hit", bodies["for_dir"])
    write_file(roots["mr_ok"] / "mr" / "ok", bodies["mr_ok"])
    write_file(roots["nested"] / "nested" / "api", bodies["nested"])

    reload_branch = ""
    reload_server_config = ""
    if include_reload_server:
        reload_root = case_dir / "www" / variant / "reload"
        write_file(reload_root / "index.html", "RELOAD_ONLY")
        write_file(reload_root / "reload-only", "RELOAD_ONLY")
        reload_branch = """              elif starts-with ${REQ.path} "/reload-only" then
                  call-server reload_dir;
"""
        reload_server_config = f"""
  reload.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server reload_dir;

  reload_dir:
    type: dir
    root_path: {reload_root}
"""

    local_dns = case_dir / f"local_dns_{variant}.toml"
    write_file(
        local_dns,
        textwrap.dedent(
            f"""
            ["www.buckyos.com"]
            ttl = 300
            address = ["{dns_address}"]
            """
        ).strip()
        + "\n",
    )

    dump_file = case_dir / "tcp.dump"

    config = f"""
user_name: app_user
password: app_pass
control_port: {ports['control']}

collections:
  test_set:
    type: memory_set
  test_map:
    type: memory_map
  route_set:
    type: memory_set

stacks:
  entry:
    bind: 127.0.0.1:{ports['entry']}
    protocol: tcp
    io_dump_file: {dump_file}
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;

  proxy_entry:
    bind: 127.0.0.1:{ports['proxy']}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;

  dns_entry:
    bind: 127.0.0.1:{ports['dns']}
    protocol: udp
    transparent: false
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server main_dns;

  socks_stack:
    bind: 127.0.0.1:{ports['socks']}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server socks_proxy;

  upstream_socks_stack:
    bind: 127.0.0.1:{ports['upstream_socks']}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server upstream_socks;

servers:
  acme_response:
    type: acme_response

  dir.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server dir_case;

  gzip.test:
    type: http
    gzip: true
    gzip_vary: true
    gzip_types:
      - text/html
      - text/plain
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server gzip_dir;

  complex.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              set-add test_set ${{REQ.path}};
              map-add test_map ${{REQ.path}} hit;
              if starts-with ${{REQ.path}} "/if/dir" then
                  call-server if_dir;
              elif starts-with ${{REQ.path}} "/if/forward" then
                  forward "http://127.0.0.1:{upstream_port}";
              elif starts-with ${{REQ.path}} "/if/reject" then
                  reject;
              elif starts-with ${{REQ.path}} "/rewrite/" then
                  rewrite ${{REQ.path}} "/rewrite/*" "/*" && forward "http://127.0.0.1:{upstream_port}";
              elif starts-with ${{REQ.path}} "/return-forward" then
                  return "forward http://127.0.0.1:{upstream_port}";
              elif starts-with ${{REQ.path}} "/shared" then
                  exec --lib shared_router;
                  call-server shared_dir;
              elif starts-with ${{REQ.path}} "/for/" then
                  set-create route_candidates;
                  set-add route_candidates "/for/hit";
                  for item in $route_candidates then
                      if eq $item ${{REQ.path}} then
                          call-server for_dir;
                      end
                  end
                  call-server fallback_dir;
              elif starts-with ${{REQ.path}} "/mr/" then
                  match-result $(strip-prefix ${{REQ.path}} "/mr/ok")
                  ok(v)
                      call-server mr_ok_dir;
                  err(e)
                      call-server fallback_dir;
                  end
              elif starts-with ${{REQ.path}} "/nested" then
                  if eq ${{REQ.host}} "complex.test" then
                      if starts-with ${{REQ.path}} "/nested/admin" then
                          reject;
                      elif starts-with ${{REQ.path}} "/nested/api" then
                          call-server nested_dir;
                      else
                          call-server fallback_dir;
                      end
                  else
                      reject;
                  end
{reload_branch}
              else
                  call-server fallback_dir;
              end
    post_hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              map-add RESP x-pc-case runtime;

  pp.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server dir_case;
    post_hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              map-add RESP x-real-remote-port ${{REQ_real_remote_port}};

  dir_case:
    type: dir
    root_path: {roots['dir']}
  fallback_dir:
    type: dir
    root_path: {roots['fallback']}
  if_dir:
    type: dir
    root_path: {roots['if_dir']}
  shared_dir:
    type: dir
    root_path: {roots['shared']}
  for_dir:
    type: dir
    root_path: {roots['for_dir']}
  mr_ok_dir:
    type: dir
    root_path: {roots['mr_ok']}
  nested_dir:
    type: dir
    root_path: {roots['nested']}
  gzip_dir:
    type: dir
    root_path: {roots['gzip']}

{reload_server_config}
  main_dns:
    type: dns
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              resolve ${{REQ.name}} ${{REQ.record_type}} local_dns && return;
              reject;

  local_dns:
    type: local_dns
    file_path: {local_dns}

  socks_proxy:
    type: socks
    username: gateway_user
    password: gateway_pass
    target: socks://upstream_user:upstream_pass@127.0.0.1:{ports['upstream_socks']}
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              eq ${{REQ.target.port}} "{echo_direct_port}" && return "DIRECT";
              eq ${{REQ.target.port}} "{echo_proxy_port}" && return "PROXY";
              reject;

  upstream_socks:
    type: socks
    username: upstream_user
    password: upstream_pass
    target: http://127.0.0.1:0
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              eq ${{REQ.target.port}} "{echo_proxy_port}" && return "DIRECT";
              reject;

global_process_chains:
  shared_router:
    priority: 1
    blocks:
      default:
        priority: 1
        block: |
          echo "shared_router";
"""
    config_path = case_dir / "cyfs_gateway.yaml"
    write_file(config_path, textwrap.dedent(config).strip() + "\n")
    return config_path, dump_file


def render_multi_gateway_remote_config(case_dir, ports, udp_echo_port):
    roots = {
        "tcp": case_dir / "remote_www" / "tcp",
        "ptcp": case_dir / "remote_www" / "ptcp",
        "socks": case_dir / "remote_www" / "socks",
    }
    write_file(roots["tcp"] / "index.html", "REMOTE_TCP")
    write_file(roots["ptcp"] / "index.html", "REMOTE_PTCP")
    write_file(roots["socks"] / "index.html", "REMOTE_SOCKS")

    config = f"""
control_port: {ports['control']}

stacks:
  remote_http:
    bind: 127.0.0.1:{ports['http']}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;

  remote_proxy:
    bind: 0.0.0.0:{ports['proxy']}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;

  remote_udp:
    bind: 127.0.0.1:{ports['udp']}
    protocol: udp
    transparent: false
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "forward udp:///127.0.0.1:{udp_echo_port}";

  remote_socks_stack:
    bind: 127.0.0.1:{ports['socks']}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server remote_socks;

servers:
  tcp-via.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server tcp_dir;

  ptcp-via.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server ptcp_dir;
    post_hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              map-add RESP x-remote-port ${{REQ_remote_port}};
              map-add RESP x-conn-remote-port ${{REQ_conn_remote_port}};
              map-add RESP x-real-remote-port ${{REQ_real_remote_port}};

  socks-via.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server socks_dir;

  tcp_dir:
    type: dir
    root_path: {roots['tcp']}

  ptcp_dir:
    type: dir
    root_path: {roots['ptcp']}

  socks_dir:
    type: dir
    root_path: {roots['socks']}

  remote_socks:
    type: socks
    username: remote_user
    password: remote_pass
    target: http://127.0.0.1:0
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              eq ${{REQ.target.port}} "{ports['http']}" && return "DIRECT";
              reject;
"""
    config_path = case_dir / "remote_gateway.yaml"
    write_file(config_path, textwrap.dedent(config).strip() + "\n")
    return config_path


def render_multi_gateway_client_config(case_dir, ports, remote_ports):
    config = f"""
control_port: {ports['control']}

stacks:
  client_http:
    bind: 127.0.0.1:{ports['http']}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;

  client_ptcp:
    bind: 0.0.0.0:{ports['ptcp']}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && forward "ptcp://${{REQ.source_addr}}/127.0.0.1:{remote_ports['proxy']}";
              reject;

  client_udp:
    bind: 127.0.0.1:{ports['udp']}
    protocol: udp
    transparent: false
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "forward udp:///127.0.0.1:{remote_ports['udp']}";

servers:
  tcp-via.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              forward "tcp:///127.0.0.1:{remote_ports['http']}";

  socks-via.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              forward "socks://remote_user:remote_pass@127.0.0.1:{remote_ports['socks']}/127.0.0.1:{remote_ports['http']}";
"""
    config_path = case_dir / "client_gateway.yaml"
    write_file(config_path, textwrap.dedent(config).strip() + "\n")
    return config_path


def generate_rtcp_device(case_dir, name):
    case_dir.mkdir(parents=True, exist_ok=True)
    key_dir = case_dir / name
    result = subprocess.run(
        [str(BIN_PATH), "gen_rtcp_key", "-n", name, "-p", str(key_dir)],
        cwd=case_dir,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
        check=False,
    )
    assert_eq(result.returncode, 0, f"gen_rtcp_key {name} exit code")
    key_path = key_dir / "device.key.pem"
    doc_path = key_dir / "device.doc.json"
    if not key_path.exists():
        fail(f"gen_rtcp_key {name} did not create device.key.pem")
    if not doc_path.exists():
        fail(f"gen_rtcp_key {name} did not create device.doc.json")
    doc = json.loads(doc_path.read_text(encoding="utf-8"))
    did = doc.get("id")
    if not isinstance(did, str) or not did.startswith("did:dev:"):
        fail(f"invalid generated RTCP DID for {name}: {did!r}")
    return {
        "key": key_path,
        "doc": doc_path,
        "did": did,
        "host": did.replace("did:dev:", "", 1) + ".dev.did",
    }


def rtcp_stack_authority(device, port):
    bootstrap = quote(f"tcp:///127.0.0.1:{port}", safe="")
    return f"{bootstrap}@{device['host']}:{port}"


def load_rtcp_fixture_device(config_path):
    config_path = Path(config_path)
    data = json.loads(config_path.read_text(encoding="utf-8"))
    did = data.get("id")
    if not isinstance(did, str) or not did.startswith("did:dev:"):
        fail(f"invalid fixture RTCP device id in {config_path}: {did!r}")
    return {
        "doc": config_path,
        "did": did,
        "host": did.replace("did:dev:", "", 1) + ".dev.did",
    }


def render_rtcp_remote_config(case_dir, ports, remote_device, keep_tunnel_targets=None):
    root = case_dir / "remote_www" / "rtcp"
    write_file(root / "index.html", "REMOTE_RTCP")
    keep_tunnel_targets = keep_tunnel_targets or []
    keep_tunnel_config = ""
    if keep_tunnel_targets:
        keep_tunnel_lines = "\n".join(f"      - {target}" for target in keep_tunnel_targets)
        keep_tunnel_config = f"    keep_tunnel:\n{keep_tunnel_lines}\n"
    config = f"""
control_port: {ports['control']}

stacks:
  remote_rtcp:
    bind: 127.0.0.1:{ports['rtcp']}
    protocol: rtcp
    key_path: {remote_device['key']}
    device_config_path: {remote_device['doc']}
{keep_tunnel_config.rstrip()}
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "forward tcp:///127.0.0.1:{ports['http']}";

  remote_http:
    bind: 127.0.0.1:{ports['http']}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;

servers:
  rtcp-via.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server rtcp_dir;

  rtcp_dir:
    type: dir
    root_path: {root}
"""
    config_path = case_dir / "remote_rtcp_gateway.yaml"
    write_file(config_path, textwrap.dedent(config).strip() + "\n")
    return config_path


def render_rtcp_client_config(
    case_dir,
    ports,
    client_device,
    remote_device,
    remote_ports,
    client_http_stack_forward_to_remote=False,
    use_bootstrap_rtcp_url=True,
):
    remote_authority = rtcp_stack_authority(remote_device, remote_ports["rtcp"])
    if not use_bootstrap_rtcp_url:
        remote_authority = f"{remote_device['host']}:{remote_ports['rtcp']}"
    remote_rtcp_url = f"rtcp://{remote_authority}/rtcp-via.test:80"
    client_http_rule = f"""http-probe && call-server ${{REQ.dest_host}};
              reject;"""
    if client_http_stack_forward_to_remote:
        client_http_rule = f'return "forward {remote_rtcp_url}";'
    config = f"""
control_port: {ports['control']}

stacks:
  client_http:
    bind: 127.0.0.1:{ports['http']}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              {client_http_rule}

  client_rtcp:
    bind: 127.0.0.1:{ports['rtcp']}
    protocol: rtcp
    key_path: {client_device['key']}
    device_config_path: {client_device['doc']}
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              reject;

servers:
  rtcp-via.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              forward "{remote_rtcp_url}";
"""
    config_path = case_dir / "client_rtcp_gateway.yaml"
    write_file(config_path, textwrap.dedent(config).strip() + "\n")
    return config_path


def start_rtcp_gateway_pair(
    case_dir,
    remote_keep_tunnel_to_client=False,
    client_http_stack_forward_to_remote=False,
    debug_rtcp_logs=False,
    client_uses_bootstrap_rtcp_url=True,
):
    remote_device = generate_rtcp_device(case_dir / "devices", "remote-rtcp")
    client_device = generate_rtcp_device(case_dir / "devices", "client-rtcp")
    remote_ports = {
        "control": free_port(),
        "http": free_port(),
        "rtcp": free_port(),
    }
    client_ports = {
        "control": free_port(),
        "http": free_port(),
        "rtcp": free_port(),
    }
    keep_tunnel_targets = []
    if remote_keep_tunnel_to_client:
        keep_tunnel_target = rtcp_stack_authority(client_device, client_ports["rtcp"])
        keep_tunnel_targets.append(keep_tunnel_target)
        remote_ports["keep_tunnel_url"] = f"rtcp://{keep_tunnel_target}"
    remote_config = render_rtcp_remote_config(
        case_dir / "remote",
        remote_ports,
        remote_device,
        keep_tunnel_targets=keep_tunnel_targets,
    )
    client_config = render_rtcp_client_config(
        case_dir / "client",
        client_ports,
        client_device,
        remote_device,
        remote_ports,
        client_http_stack_forward_to_remote=client_http_stack_forward_to_remote,
        use_bootstrap_rtcp_url=client_uses_bootstrap_rtcp_url,
    )
    extra_env = {"BUCKY_LOG": "debug"} if debug_rtcp_logs else None
    remote = GatewayProcess(
        case_dir / "remote",
        remote_config,
        case_dir / "remote-root",
        extra_env=extra_env,
    )
    client = GatewayProcess(
        case_dir / "client",
        client_config,
        case_dir / "client-root",
        extra_env=extra_env,
    )
    try:
        if remote_keep_tunnel_to_client:
            client.start()
            wait_gateway_ready(client, client_ports["control"])
            wait_tcp_port(client, client_ports["http"], "client http")
            wait_tcp_port(client, client_ports["rtcp"], "client rtcp")
            remote.start()
            wait_gateway_ready(remote, remote_ports["control"])
            wait_tcp_port(remote, remote_ports["http"], "remote rtcp http")
            wait_tcp_port(remote, remote_ports["rtcp"], "remote rtcp")
        else:
            remote.start()
            wait_gateway_ready(remote, remote_ports["control"])
            wait_tcp_port(remote, remote_ports["http"], "remote rtcp http")
            wait_tcp_port(remote, remote_ports["rtcp"], "remote rtcp")
            client.start()
            wait_gateway_ready(client, client_ports["control"])
            wait_tcp_port(client, client_ports["http"], "client http")
            wait_tcp_port(client, client_ports["rtcp"], "client rtcp")
    except Exception:
        client.stop()
        remote.stop()
        raise
    return remote, client, remote_ports, client_ports


def stop_rtcp_gateway_pair(resources):
    remote, client, _remote_ports, _client_ports = resources
    client.stop()
    remote.stop()


def start_multi_gateway_pair(case_dir):
    udp_echo = UdpEchoServer(prefix=b"REMOTE_UDP:")
    udp_echo.start()
    remote_ports = {
        "control": free_port(),
        "http": free_port(),
        "proxy": free_port(),
        "udp": free_udp_port(),
        "socks": free_port(),
    }
    client_ports = {
        "control": free_port(),
        "http": free_port(),
        "ptcp": free_port(),
        "udp": free_udp_port(),
    }
    remote_config = render_multi_gateway_remote_config(
        case_dir / "remote",
        remote_ports,
        udp_echo.port,
    )
    client_config = render_multi_gateway_client_config(
        case_dir / "client",
        client_ports,
        remote_ports,
    )
    remote = GatewayProcess(case_dir / "remote", remote_config, case_dir / "remote-root")
    client = GatewayProcess(case_dir / "client", client_config, case_dir / "client-root")
    remote.start()
    try:
        wait_gateway_ready(remote, remote_ports["control"])
        for name in ("http", "proxy", "socks"):
            wait_tcp_port(remote, remote_ports[name], f"remote {name}")
        client.start()
        wait_gateway_ready(client, client_ports["control"])
        wait_tcp_port(client, client_ports["http"], "client http")
        wait_tcp_port(client, client_ports["ptcp"], "client ptcp")
    except Exception:
        client.stop()
        remote.stop()
        udp_echo.stop()
        raise
    return remote, client, udp_echo, remote_ports, client_ports


def stop_multi_gateway_pair(resources):
    remote, client, udp_echo, _remote_ports, _client_ports = resources
    client.stop()
    remote.stop()
    udp_echo.stop()


def generate_self_signed_cert(cert_path, key_path, common_name):
    cert_path = Path(cert_path)
    key_path = Path(key_path)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "30",
            "-subj",
            f"/CN={common_name}",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=20,
        check=False,
    )
    assert_process_ok(result, f"generate self-signed cert for {common_name}")


def install_tls_identity_cert(buckyos_root, host):
    public_dir = Path(buckyos_root) / "local" / "identity" / host
    security_dir = Path(buckyos_root) / "security" / host
    cert_path = public_dir / "server.fullchain.pem"
    key_path = security_dir / "server.private.pem"
    public_dir.mkdir(parents=True, exist_ok=True)
    security_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "30",
            "-subj",
            f"/CN={host}",
            "-addext",
            f"subjectAltName=DNS:{host}",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=20,
        check=False,
    )
    assert_process_ok(result, f"generate TLS identity cert for {host}")


def generate_named_rtcp_files(target_dir, name, key_name, doc_name):
    key_dir = Path(target_dir) / f"_{name}_rtcp_key"
    result = subprocess.run(
        [str(BIN_PATH), "gen_rtcp_key", "-n", name, "-p", str(key_dir)],
        cwd=target_dir,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
        check=False,
    )
    assert_process_ok(result, f"gen_rtcp_key {name}")
    key_path = key_dir / "device.key.pem"
    doc_path = key_dir / "device.doc.json"
    if not key_path.exists() or not doc_path.exists():
        fail(f"gen_rtcp_key {name} did not create expected files")
    target_key = Path(target_dir) / key_name
    target_doc = Path(target_dir) / doc_name
    shutil.copyfile(key_path, target_key)
    shutil.copyfile(doc_path, target_doc)
    return target_key, target_doc


def generate_buckyos_config_gen_files(runtime_dir):
    node_root = Path(runtime_dir) / "buckyos-node"
    node_etc = node_root / "etc"
    web3_dir = Path(runtime_dir) / "web3-gateway"
    node_etc.mkdir(parents=True, exist_ok=True)
    web3_dir.mkdir(parents=True, exist_ok=True)

    _node_key, node_doc = generate_named_rtcp_files(
        node_etc,
        "ood1",
        "node_private_key.pem",
        "node_device_config.json",
    )
    generate_named_rtcp_files(
        web3_dir,
        "sn",
        "sn_private_key.pem",
        "sn_device_config.json",
    )

    node_device = json.loads(node_doc.read_text(encoding="utf-8"))
    node_public_key = node_device["verificationMethod"][0]["publicKeyJwk"]
    write_file(
        node_etc / "node_identity.json",
        json.dumps(
            {
                "zone_did": "did:bns:alice",
                "owner_public_key": node_public_key,
                "owner_did": "did:bns:alice",
                "device_doc_jwt": "",
                "device_mini_doc_jwt": "",
                "zone_iat": int(time.time()),
            },
            indent=2,
        ),
    )
    write_file(
        node_etc / "node_gateway_info.json",
        json.dumps(
            {
                "node_info": {},
                "app_info": {},
                "service_info": {},
                "node_route_map": {},
                "routes": {},
                "trust_key": {},
            },
            indent=2,
        ),
    )
    write_file(node_etc / "node_gateway.json", "{}\n")
    write_file(node_etc / "user_gateway.yaml", "# generated user gateway config\n--- {}\n")
    write_file(node_etc / "boot_gateway.yaml", "# generated by cyfs_gateway_app integration test\n--- {}\n")
    write_file(node_etc / "post_gateway.yaml", "# generated post gateway config\n--- {}\n")
    write_file(node_etc / "cyfs_gateway.yaml", "includes:\n- path: user_gateway.yaml\n- path: boot_gateway.yaml\n- path: node_gateway.json\n- path: post_gateway.yaml\n")
    generate_self_signed_cert(
        node_etc / "zone_cert.cert",
        node_etc / "zone_cert_key.pem",
        "alice.web3.devtests.org",
    )

    params = {
        "params": {
            "sn_boot_jwt": "",
            "sn_cer": "fullchain.cert",
            "sn_device_jwt": "",
            "sn_host": "devtests.org",
            "sn_ip": "127.0.0.1",
            "sn_owner_pk": "",
            "sn_pem": "fullchain.pem",
            "web3_cer": "fullchain.cert",
            "web3_pem": "fullchain.pem",
        }
    }
    write_file(web3_dir / "params.json", json.dumps(params, indent=2))
    write_file(web3_dir / "sn_db.sqlite3", "")
    generate_self_signed_cert(
        web3_dir / "fullchain.cert",
        web3_dir / "fullchain.pem",
        "devtests.org",
    )
    return node_root, node_etc, web3_dir


def render_buckyos_fixture_node_config(case_dir, fixture_node_etc, ports, upstream_port):
    config = f"""
control_port: {ports['control']}

stacks:
  node_rtcp:
    protocol: rtcp
    bind: 127.0.0.1:{ports['rtcp']}
    key_path: {fixture_node_etc / "node_private_key.pem"}
    device_config_path: {fixture_node_etc / "node_device_config.json"}
    keep_tunnel: []
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "forward tcp:///127.0.0.1:{upstream_port}";

  node_http:
    protocol: tcp
    bind: 127.0.0.1:{ports['http']}
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server node_http_api;
              reject;

servers:
  node_http_api:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              map-add REQ path "/";
              forward "http://127.0.0.1:{upstream_port}";
"""
    config_path = case_dir / "cyfs_gateway.yaml"
    write_file(config_path, textwrap.dedent(config).strip() + "\n")
    return config_path


def render_web3_fixture_gateway_config(
    case_dir, fixture_web3_dir, ports, node_rtcp_target, bns_rpc_url
):
    params = json.loads((fixture_web3_dir / "params.json").read_text(encoding="utf-8"))["params"]
    sn_db = case_dir / "sn_db.sqlite3"
    config = f"""
control_port: {ports['control']}

stacks:
  web3_rtcp:
    protocol: rtcp
    bind: 127.0.0.1:{ports['rtcp']}
    key_path: {fixture_web3_dir / "sn_private_key.pem"}
    device_config_path: {fixture_web3_dir / "sn_device_config.json"}
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              reject;

  web3_http:
    protocol: tcp
    bind: 127.0.0.1:{ports['http']}
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server web3-export.test;
              reject;

servers:
  web3-export.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              if starts-with ${{REQ.path}} "/sn" then
                rewrite ${{REQ.path}} "/sn/*" "/*" && call-server sn;
              else
                forward "rtcp://{node_rtcp_target}/buckyos-node.test:80";
              end

  sn:
    type: sn
    host: {json.dumps(params["sn_host"])}
    ip: {json.dumps(params["sn_ip"])}
    boot_jwt: {json.dumps(params["sn_boot_jwt"])}
    owner_pkx: {json.dumps(params["sn_owner_pk"])}
    device_jwt:
      - {json.dumps(params["sn_device_jwt"])}
    db_type: sqlite
    db_path: {sn_db}
    bns_rpc_url: {json.dumps(bns_rpc_url)}
    bns_evm:
      controller_private_key: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
"""
    config_path = case_dir / "web3_gateway.yaml"
    write_file(config_path, textwrap.dedent(config).strip() + "\n")
    return config_path


def assert_web3_to_buckyos_node_roundtrip(web3_ports):
    last_error = None
    for _ in range(80):
        try:
            status, _, body = http_text(web3_ports["http"], "web3-export.test", "/")
            if status == 200 and body.startswith("upstream:"):
                return
            last_error = f"status={status}, body={body!r}"
        except Exception as exc:
            last_error = exc
        time.sleep(0.25)
    fail(f"web3 gateway did not reach buckyos node http via rtcp: {last_error}")


def run_gateway_case(name, case_func):
    print(f"[cyfs-gateway-app] case={name}")
    with tempfile.TemporaryDirectory(prefix=f"cyfs-gateway-{name}-") as tmp:
        case_dir = Path(tmp)
        try:
            case_func(case_dir)
        except Exception:
            print(f"[cyfs-gateway-app] failed case dir: {case_dir}")
            raise


def test_minimal_startup_and_dir_routing(case_dir):
    upstream = UpstreamServer()
    upstream.start()
    gateway = None
    try:
        entry_port = free_port()
        config_path = render_runtime_config(case_dir, entry_port, upstream.port)
        gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
        gateway.start()
        wait_gateway_ready(gateway, gateway.control_port)

        status, headers, body = http_text(entry_port, "dir.test", "/")
        assert_eq(status, 200, "dir route status")
        assert_eq(body, "DIR", "dir route body")
    finally:
        if gateway is not None:
            gateway.stop()
        upstream.stop()


def test_process_chain_runtime_routes(case_dir):
    upstream = UpstreamServer()
    upstream.start()
    gateway = None
    try:
        entry_port = free_port()
        config_path = render_runtime_config(case_dir, entry_port, upstream.port)
        gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
        gateway.start()
        wait_gateway_ready(gateway, gateway.control_port)

        status, headers, body = http_text(entry_port, "pc.test", "/if/dir")
        assert_eq(status, 200, "if dir status")
        assert_eq(body, "IF_DIR", "if dir body")
        assert_eq(headers.get("x-pc-case"), "runtime", "post hook header")

        status, _, body = http_text(entry_port, "pc.test", "/if/forward")
        assert_eq(status, 200, "if forward status")
        assert_endswith(body, "/if/forward", "if forward body")

        status, _, body = http_text(entry_port, "pc.test", "/rewrite/hello")
        assert_eq(status, 200, "rewrite forward status")
        assert_endswith(body, "/hello", "rewrite forward body")

        status, _, body = http_text(entry_port, "pc.test", "/return-forward")
        assert_eq(status, 200, "return forward status")
        assert_endswith(body, "/return-forward", "return forward body")

        status, _, body = http_text(entry_port, "pc.test", "/fallback")
        assert_eq(status, 200, "fallback status")
        assert_eq(body, "FALLBACK", "fallback body")

        status, _, _ = http_text(entry_port, "pc.test", "/if/reject")
        assert_eq(status, 403, "reject status")
    finally:
        if gateway is not None:
            gateway.stop()
        upstream.stop()


def test_invalid_config_exits(case_dir):
    control_port = free_port()
    config = f"""
stacks:
  bad:
    bind: 127.0.0.1:{control_port}
    protocol: definitely_unknown
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              reject;
servers: {{}}
"""
    config_path = case_dir / "bad.yaml"
    write_file(config_path, textwrap.dedent(config).strip() + "\n")
    gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
    try:
        gateway.start()
        try:
            gateway.proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            fail("invalid config process did not exit")
        output = gateway.output()
        assert_in("unknown protocol", output, "invalid config output")
    finally:
        gateway.stop()


def test_cli_help_and_gen_rtcp_key(case_dir):
    help_result = subprocess.run(
        [str(BIN_PATH), "--help"],
        cwd=case_dir,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
        check=False,
    )
    assert_eq(help_result.returncode, 0, "help exit code")
    assert_in("CYFS Gateway Service", help_result.stdout, "help output")

    key_dir = case_dir / "keys"
    key_result = subprocess.run(
        [str(BIN_PATH), "gen_rtcp_key", "-n", "test-device", "-p", str(key_dir)],
        cwd=case_dir,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
        check=False,
    )
    assert_eq(key_result.returncode, 0, "gen_rtcp_key exit code")
    if not (key_dir / "device.key.pem").exists():
        fail("gen_rtcp_key did not create device.key.pem")
    doc_path = key_dir / "device.doc.json"
    if not doc_path.exists():
        fail("gen_rtcp_key did not create device.doc.json")
    json.loads(doc_path.read_text(encoding="utf-8"))


def start_full_gateway(case_dir):
    upstream = UpstreamServer()
    direct_echo = EchoServer()
    proxy_echo = EchoServer()
    upstream.start()
    direct_echo.start()
    proxy_echo.start()
    ports = {
        "control": free_port(),
        "entry": free_port(),
        "proxy": free_port(),
        "dns": free_udp_port(),
        "socks": free_port(),
        "upstream_socks": free_port(),
    }
    config_path, dump_file = render_full_runtime_config(
        case_dir,
        ports,
        upstream.port,
        direct_echo.port,
        proxy_echo.port,
    )
    gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
    gateway.start()
    try:
        wait_gateway_ready(gateway, ports["control"])
        for name in ("entry", "socks", "upstream_socks"):
            wait_tcp_port(gateway, ports[name], name)
    except Exception:
        gateway.stop()
        upstream.stop()
        direct_echo.stop()
        proxy_echo.stop()
        raise
    return gateway, upstream, direct_echo, proxy_echo, ports, dump_file


def stop_full_gateway(resources):
    gateway, upstream, direct_echo, proxy_echo, _ports, _dump_file = resources
    gateway.stop()
    upstream.stop()
    direct_echo.stop()
    proxy_echo.stop()


def test_full_process_chain_runtime(case_dir):
    resources = start_full_gateway(case_dir)
    gateway, upstream, direct_echo, proxy_echo, ports, dump_file = resources
    try:
        status, _, body = http_text(ports["entry"], "dir.test", "/")
        assert_eq(status, 200, "host routing status")
        assert_eq(body, "DIR", "host routing body")

        status, headers, body = http_text(ports["entry"], "complex.test", "/if/dir")
        assert_eq(status, 200, "if dir status")
        assert_eq(body, "IF_DIR", "if dir body")
        assert_eq(headers.get("x-pc-case"), "runtime", "post hook header")

        status, _, body = http_text(ports["entry"], "complex.test", "/if/forward")
        assert_eq(status, 200, "if forward status")
        assert_endswith(body, "/if/forward", "if forward body")

        status, _, body = http_text(ports["entry"], "complex.test", "/rewrite/hello")
        assert_eq(status, 200, "rewrite status")
        assert_endswith(body, "/hello", "rewrite body")

        status, _, body = http_text(ports["entry"], "complex.test", "/return-forward")
        assert_eq(status, 200, "return forward status")
        assert_endswith(body, "/return-forward", "return forward body")

        status, _, body = http_text(ports["entry"], "complex.test", "/shared")
        assert_eq(status, 200, "global chain status")
        assert_eq(body, "SHARED", "global chain body")

        status, _, body = http_text(ports["entry"], "complex.test", "/for/hit")
        assert_eq(status, 200, "for router status")
        assert_eq(body, "FOR_DIR", "for router body")

        status, _, body = http_text(ports["entry"], "complex.test", "/mr/ok")
        assert_eq(status, 200, "match-result ok status")
        assert_eq(body, "MR_OK", "match-result ok body")

        status, _, body = http_text(ports["entry"], "complex.test", "/mr/miss")
        assert_eq(status, 200, "match-result err status")
        assert_eq(body, "FALLBACK", "match-result err body")

        status, _, body = http_text(ports["entry"], "complex.test", "/nested/api")
        assert_eq(status, 200, "nested if status")
        assert_eq(body, "NESTED", "nested if body")

        status, _, _ = http_text(ports["entry"], "complex.test", "/nested/admin")
        assert_eq(status, 403, "nested reject status")

        status, _, _ = http_text(ports["entry"], "complex.test", "/if/reject")
        assert_eq(status, 403, "reject status")

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if dump_file.exists() and b"CGDP" in dump_file.read_bytes():
                break
            time.sleep(0.1)
        else:
            fail("io dump frame was not written")
    finally:
        stop_full_gateway(resources)


def test_gzip_dns_socks_and_proxy_protocol(case_dir):
    resources = start_full_gateway(case_dir)
    gateway, upstream, direct_echo, proxy_echo, ports, _dump_file = resources
    try:
        status, headers, body = http_request(
            ports["entry"],
            "gzip.test",
            "/",
            headers={"Accept-Encoding": "gzip"},
        )
        assert_eq(status, 200, "gzip status")
        assert_eq(headers.get("content-encoding"), "gzip", "gzip response encoding")
        assert_in("gzip-body-", gzip.decompress(body).decode("utf-8"), "gzip body")

        status, headers, body = http_text(ports["entry"], "gzip.test", "/")
        assert_eq(status, 200, "plain gzip server status")
        assert_true("content-encoding" not in headers, "plain response should not be gzip")
        assert_in("gzip-body-", body, "plain gzip server body")

        addrs = dns_query_a(ports["dns"], "www.buckyos.com")
        assert_in("192.168.1.1", addrs, "local dns answer")

        with socks5_connect(ports["socks"], "gateway_user", "gateway_pass", direct_echo.port) as s:
            s.sendall(b"socks-direct")
            assert_eq(s.recv(64), b"socks-direct", "socks direct echo")

        with socks5_connect(ports["socks"], "gateway_user", "gateway_pass", proxy_echo.port) as s:
            s.sendall(b"socks-proxy")
            assert_eq(s.recv(64), b"socks-proxy", "socks proxy echo")

        reject_port = free_port()
        try:
            s = socks5_connect(ports["socks"], "gateway_user", "gateway_pass", reject_port)
        except OSError:
            pass
        else:
            s.close()
            fail("socks reject target unexpectedly connected")

        with socket.create_connection(("127.0.0.1", ports["proxy"]), timeout=5) as sock:
            sock.settimeout(5)
            sock.sendall(
                b"PROXY TCP4 10.0.0.1 127.0.0.1 12345 80\r\n"
                b"GET / HTTP/1.1\r\nHost: pp.test\r\nConnection: close\r\n\r\n"
            )
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            data = b"".join(chunks).decode("utf-8", errors="replace")
        assert_in("200 OK", data, "proxy protocol response")
        assert_in("DIR", data, "proxy protocol response body")
    finally:
        stop_full_gateway(resources)


def test_reload_runtime_workloads(case_dir):
    resources = start_full_gateway(case_dir)
    gateway, upstream, direct_echo, proxy_echo, ports, _dump_file = resources
    try:
        status, _, body = http_text(ports["entry"], "dir.test", "/")
        assert_eq(status, 200, "pre-reload dir status")
        assert_eq(body, "DIR", "pre-reload dir body")
        addrs = dns_query_a(ports["dns"], "www.buckyos.com")
        assert_in("192.168.1.1", addrs, "pre-reload dns answer")

        render_full_runtime_config(
            case_dir,
            ports,
            upstream.port,
            direct_echo.port,
            proxy_echo.port,
            variant="reloaded",
            dns_address="192.168.1.2",
            include_reload_server=True,
        )
        token = control_login(ports["control"])
        control_reload(ports["control"], token)

        deadline = time.monotonic() + 10
        while True:
            try:
                status, _, body = http_text(ports["entry"], "dir.test", "/")
                if status == 200 and body == "DIR_RELOADED":
                    break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                fail("reloaded dir.test did not become ready")
            time.sleep(0.1)

        status, _, body = http_text(ports["entry"], "reload.test", "/")
        assert_eq(status, 200, "reload-only host status")
        assert_eq(body, "RELOAD_ONLY", "reload-only host body")

        status, headers, body = http_text(ports["entry"], "complex.test", "/if/dir")
        assert_eq(status, 200, "reloaded if dir status")
        assert_eq(body, "IF_DIR_RELOADED", "reloaded if dir body")
        assert_eq(headers.get("x-pc-case"), "runtime", "reloaded post hook header")

        status, _, body = http_text(ports["entry"], "complex.test", "/if/forward")
        assert_eq(status, 200, "reloaded forward status")
        assert_endswith(body, "/if/forward", "reloaded forward body")

        status, _, body = http_text(ports["entry"], "complex.test", "/shared")
        assert_eq(status, 200, "reloaded global chain status")
        assert_eq(body, "SHARED_RELOADED", "reloaded global chain body")

        status, _, body = http_text(ports["entry"], "complex.test", "/for/hit")
        assert_eq(status, 200, "reloaded for router status")
        assert_eq(body, "FOR_DIR_RELOADED", "reloaded for router body")

        status, _, body = http_text(ports["entry"], "complex.test", "/mr/ok")
        assert_eq(status, 200, "reloaded match-result ok status")
        assert_eq(body, "MR_OK_RELOADED", "reloaded match-result ok body")

        status, _, body = http_text(ports["entry"], "complex.test", "/mr/miss")
        assert_eq(status, 200, "reloaded match-result err status")
        assert_eq(body, "FALLBACK_RELOADED", "reloaded match-result err body")

        status, _, body = http_text(ports["entry"], "complex.test", "/nested/api")
        assert_eq(status, 200, "reloaded nested status")
        assert_eq(body, "NESTED_RELOADED", "reloaded nested body")

        status, _, body = http_text(ports["entry"], "complex.test", "/reload-only")
        assert_eq(status, 200, "reloaded branch status")
        assert_eq(body, "RELOAD_ONLY", "reloaded branch body")

        status, headers, body = http_request(
            ports["entry"],
            "gzip.test",
            "/",
            headers={"Accept-Encoding": "gzip"},
        )
        assert_eq(status, 200, "reloaded gzip status")
        assert_eq(headers.get("content-encoding"), "gzip", "reloaded gzip response encoding")
        assert_in("gzip-reloaded-body-", gzip.decompress(body).decode("utf-8"), "reloaded gzip body")

        addrs = dns_query_a(ports["dns"], "www.buckyos.com")
        assert_in("192.168.1.2", addrs, "reloaded dns answer")

        with socks5_connect(ports["socks"], "gateway_user", "gateway_pass", direct_echo.port) as s:
            s.sendall(b"reload-socks-direct")
            assert_eq(s.recv(64), b"reload-socks-direct", "reloaded socks direct echo")

        with socks5_connect(ports["socks"], "gateway_user", "gateway_pass", proxy_echo.port) as s:
            s.sendall(b"reload-socks-proxy")
            assert_eq(s.recv(64), b"reload-socks-proxy", "reloaded socks proxy echo")

        with socket.create_connection(("127.0.0.1", ports["proxy"]), timeout=5) as sock:
            sock.settimeout(5)
            sock.sendall(
                b"PROXY TCP4 10.0.0.2 127.0.0.1 23456 80\r\n"
                b"GET / HTTP/1.1\r\nHost: pp.test\r\nConnection: close\r\n\r\n"
            )
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            data = b"".join(chunks).decode("utf-8", errors="replace")
        assert_in("200 OK", data, "reloaded proxy protocol response")
        assert_in("DIR_RELOADED", data, "reloaded proxy protocol response body")
    finally:
        stop_full_gateway(resources)


def test_multi_gateway_tunnel_protocols(case_dir):
    resources = start_multi_gateway_pair(case_dir)
    _remote, _client, _udp_echo, _remote_ports, client_ports = resources
    try:
        status, _, body = http_text(client_ports["http"], "tcp-via.test", "/")
        assert_eq(status, 200, "multi gateway tcp tunnel status")
        assert_eq(body, "REMOTE_TCP", "multi gateway tcp tunnel body")

        source_port, status, headers, body = raw_http_get_with_bound_source(
            client_ports["ptcp"], "ptcp-via.test", "/"
        )
        assert_eq(status, 200, "multi gateway ptcp tunnel status")
        assert_eq(body, "REMOTE_PTCP", "multi gateway ptcp tunnel body")
        assert_eq(
            int(headers.get("x-remote-port", "0")),
            source_port,
            "multi gateway ptcp remote port",
        )
        assert_eq(
            int(headers.get("x-real-remote-port", "0")),
            source_port,
            "multi gateway ptcp real remote port",
        )
        assert_true(
            int(headers.get("x-conn-remote-port", "0")) != source_port,
            "multi gateway ptcp conn remote port",
        )

        status, _, body = http_text(client_ports["http"], "socks-via.test", "/")
        assert_eq(status, 200, "multi gateway socks tunnel status")
        assert_eq(body, "REMOTE_SOCKS", "multi gateway socks tunnel body")

        data = udp_roundtrip(client_ports["udp"], b"datagram")
        assert_eq(data, b"REMOTE_UDP:datagram", "multi gateway udp tunnel response")
    finally:
        stop_multi_gateway_pair(resources)


def assert_rtcp_app_tunnel_roundtrip(client_ports):
    deadline = time.monotonic() + 15
    last_error = None
    while True:
        try:
            status, _, body = http_text(client_ports["http"], "rtcp-via.test", "/")
            if status == 200 and body == "REMOTE_RTCP":
                break
            last_error = f"status={status}, body={body!r}"
        except Exception as exc:
            last_error = str(exc)
        if time.monotonic() >= deadline:
            fail(f"rtcp app tunnel did not become ready: {last_error}")
        time.sleep(0.2)


def test_rtcp_app_tunnel_roundtrip(case_dir):
    resources = start_rtcp_gateway_pair(case_dir)
    _remote, _client, _remote_ports, client_ports = resources
    try:
        assert_rtcp_app_tunnel_roundtrip(client_ports)
    finally:
        stop_rtcp_gateway_pair(resources)


def test_rtcp_app_tunnel_roundtrip_with_remote_keep_tunnel_ropen(case_dir):
    resources = start_rtcp_gateway_pair(
        case_dir,
        remote_keep_tunnel_to_client=True,
        client_http_stack_forward_to_remote=True,
        debug_rtcp_logs=True,
        client_uses_bootstrap_rtcp_url=False,
    )
    remote, client, remote_ports, client_ports = resources
    try:
        wait_process_output_contains(
            remote,
            f"Will keep tunnel: {remote_ports['keep_tunnel_url']}",
            "remote rtcp keep_tunnel to client",
        )
        assert_rtcp_app_tunnel_roundtrip(client_ports)
        print(
            "[cyfs-gateway-app] rtcp ropen roundtrip: "
            "client http -> remote rtcp dir returned REMOTE_RTCP"
        )
        wait_process_output_contains(
            client,
            "post ropen sent:",
            "client sent RTCP ROpen while reusing remote keep_tunnel",
        )
        wait_process_output_contains(
            remote,
            "RTcp tunnel ropen request:",
            "remote handled RTCP ROpen command",
        )
        # print_process_output_matches(
        #     client,
        #     "rtcp ropen client",
        #     [
        #         "Reuse tunnel",
        #         "can_direct:false",
        #         "post ropen",
        #         "wait ropen stream",
        #     ],
        # )
        # print_process_output_matches(
        #     remote,
        #     "rtcp ropen remote",
        #     [
        #         "Will keep tunnel:",
        #         "RTcp tunnel ropen request:",
        #         "ropen ack sent:",
        #         "accept new stream:",
        #     ],
        # )
    finally:
        stop_rtcp_gateway_pair(resources)


def test_rtcp_app_tunnel_roundtrip_with_remote_keep_tunnel(case_dir):
    resources = start_rtcp_gateway_pair(case_dir, remote_keep_tunnel_to_client=True)
    _remote, _client, remote_ports, client_ports = resources
    try:
        wait_process_output_contains(
            _remote,
            f"Will keep tunnel: {remote_ports['keep_tunnel_url']}",
            "remote rtcp keep_tunnel to client",
        )
        assert_rtcp_app_tunnel_roundtrip(client_ports)
    finally:
        stop_rtcp_gateway_pair(resources)


def test_rtcp_app_tunnel_roundtrip_with_client_http_stack_forward(case_dir):
    resources = start_rtcp_gateway_pair(case_dir, client_http_stack_forward_to_remote=True)
    _remote, _client, _remote_ports, client_ports = resources
    try:
        assert_rtcp_app_tunnel_roundtrip(client_ports)
    finally:
        stop_rtcp_gateway_pair(resources)


def test_rtcp_app_tunnel_roundtrip_with_client_http_stack_forward_and_remote_keep_tunnel(case_dir):
    resources = start_rtcp_gateway_pair(
        case_dir,
        remote_keep_tunnel_to_client=True,
        client_http_stack_forward_to_remote=True,
    )
    _remote, _client, remote_ports, client_ports = resources
    try:
        wait_process_output_contains(
            _remote,
            f"Will keep tunnel: {remote_ports['keep_tunnel_url']}",
            "remote rtcp keep_tunnel to client",
        )
        assert_rtcp_app_tunnel_roundtrip(client_ports)
    finally:
        stop_rtcp_gateway_pair(resources)


def test_buckyos_config_gen_web3_exported_http_reaches_node(case_dir):
    upstream = UpstreamServer()
    upstream.start()
    bns_rpc = BnsRpcServer()
    bns_rpc.start()
    runtime_dir = case_dir / "buckyos-config-gen"
    web3_gateway = None
    node_gateway = None
    try:
        if runtime_dir.exists():
            shutil.rmtree(runtime_dir)
        node_root, node_etc, web3_dir = generate_buckyos_config_gen_files(runtime_dir)

        node_device = load_rtcp_fixture_device(node_etc / "node_device_config.json")
        web3_device = load_rtcp_fixture_device(web3_dir / "sn_device_config.json")
        node_ports = {
            "control": free_port(),
            "http": free_port(),
            "rtcp": free_port(),
        }
        web3_ports = {
            "control": free_port(),
            "http": free_port(),
            "rtcp": free_port(),
        }
        node_rtcp_target = rtcp_stack_authority(node_device, node_ports["rtcp"])
        web3_rtcp_target = rtcp_stack_authority(web3_device, web3_ports["rtcp"])

        node_config = render_buckyos_fixture_node_config(
            node_etc,
            node_etc,
            node_ports,
            upstream.port,
        )
        web3_config = render_web3_fixture_gateway_config(
            web3_dir,
            web3_dir,
            web3_ports,
            node_rtcp_target,
            f"http://127.0.0.1:{bns_rpc.port}",
        )
        web3_gateway = GatewayProcess(web3_dir, web3_config, runtime_dir / "web3-root")
        node_gateway = GatewayProcess(
            node_root,
            node_config,
            node_root,
            extra_args=["--keep_tunnel", web3_rtcp_target],
        )
        web3_gateway.start()
        wait_gateway_ready(web3_gateway, web3_ports["control"])
        wait_tcp_port(web3_gateway, web3_ports["http"], "web3 exported http")
        wait_tcp_port(web3_gateway, web3_ports["rtcp"], "web3 rtcp")
        sn_resp = http_json_rpc(
            web3_ports["http"],
            "web3-export.test",
            "/sn/kapi/sn/auth",
            "auth.check_username",
            {"name": "itestaliceconfig"},
        )
        assert_true(sn_resp.get("result", {}).get("valid"), "web3 sn check_username result")

        node_gateway.start()
        wait_gateway_ready(node_gateway, node_ports["control"])
        wait_tcp_port(node_gateway, node_ports["http"], "buckyos node http")
        wait_tcp_port(node_gateway, node_ports["rtcp"], "buckyos node rtcp")
        wait_process_output_contains(
            node_gateway,
            f"Will keep tunnel: rtcp://{web3_rtcp_target}",
            "buckyos node keep_tunnel to web3 gateway",
            timeout_sec=10,
        )

        assert_web3_to_buckyos_node_roundtrip(web3_ports)
        assert_true(upstream.requests, "buckyos node http service received request")
        assert_eq(
            upstream.requests[-1]["method"],
            "GET",
            "buckyos node http service method",
        )
    finally:
        if node_gateway is not None:
            node_gateway.stop()
        if web3_gateway is not None:
            web3_gateway.stop()
        bns_rpc.stop()
        upstream.stop()


def test_cli_against_running_app(case_dir):
    resources = start_full_gateway(case_dir)
    gateway, upstream, direct_echo, proxy_echo, ports, _dump_file = resources
    root = case_dir / "buckyos-root"
    server = f"http://127.0.0.1:{ports['control']}"
    try:
        status, _, body = http_text(ports["entry"], "complex.test", "/shared")
        assert_eq(status, 200, "cli collection seed status")
        assert_eq(body, "SHARED", "cli collection seed body")

        token = control_login(ports["control"])
        token_path = root / "data" / "var" / "cyfs_gateway" / "cli_token" / server.lower().encode("utf-8").hex()
        write_file(token_path, token)

        doc = run_cli(["process_chain", "call-server"], case_dir, root)
        assert_process_ok(doc, "cli process_chain help exit code")
        assert_in("call-server", doc.stdout, "cli process_chain help")

        all_doc = run_cli(["process_chain", "--all"], case_dir, root, timeout=20)
        assert_process_ok(all_doc, "cli process_chain all exit code")
        assert_in("proxy-protocol-probe", all_doc.stdout, "cli process_chain all output")

        show_config = run_cli(
            ["show", "config", "--format", "yaml", "--server", server],
            case_dir,
            root,
            timeout=20,
        )
        assert_process_ok(show_config, "cli show config exit code")
        assert_in("complex.test", show_config.stdout, "cli show config user server")
        if "__control_server__" in show_config.stdout:
            fail("cli show config leaked builtin control server config")
    finally:
        stop_full_gateway(resources)


def write_minimal_yaml(path, entry_port, body="DIR", root_path=None):
    root_path = root_path or path.parent / "www"
    write_file(Path(root_path) / "index.html", body)
    config = f"""
stacks:
  entry:
    bind: 127.0.0.1:{entry_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;
servers:
  acme_response:
    type: acme_response
  dir.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server dir_case;
  dir_case:
    type: dir
    root_path: {root_path}
"""
    write_file(path, textwrap.dedent(config).strip() + "\n")


def test_config_loading_formats_and_paths(case_dir):
    for ext in ("yaml", "json", "toml"):
        sub = case_dir / ext
        sub.mkdir()
        entry_port = free_port()
        root = sub / "www"
        if ext == "yaml":
            config_path = sub / "cyfs_gateway.yaml"
            write_minimal_yaml(config_path, entry_port, body=f"DIR-{ext}", root_path=root)
        elif ext == "json":
            write_file(root / "index.html", f"DIR-{ext}")
            config_path = sub / "cyfs_gateway.json"
            config = {
                "stacks": {
                    "entry": {
                        "bind": f"127.0.0.1:{entry_port}",
                        "protocol": "tcp",
                        "hook_point": {"main": {"priority": 1, "blocks": {"default": {"priority": 1, "block": "http-probe && call-server ${REQ.dest_host};\nreject;"}}}},
                    },
                },
                "servers": {
                    "acme_response": {"type": "acme_response"},
                    "dir.test": {"type": "http", "hook_point": {"main": {"priority": 1, "blocks": {"default": {"priority": 1, "block": "call-server dir_case;"}}}}},
                    "dir_case": {"type": "dir", "root_path": str(root)},
                },
            }
            write_file(config_path, json.dumps(config))
        else:
            write_file(root / "index.html", f"DIR-{ext}")
            config_path = sub / "cyfs_gateway.toml"
            write_file(
                config_path,
                f"""
[stacks.entry]
bind = "127.0.0.1:{entry_port}"
protocol = "tcp"
[stacks.entry.hook_point.main]
priority = 1
[stacks.entry.hook_point.main.blocks.default]
priority = 1
block = '''http-probe && call-server ${{REQ.dest_host}};
reject;'''
[servers.acme_response]
type = "acme_response"
[servers."dir.test"]
type = "http"
[servers."dir.test".hook_point.main]
priority = 1
[servers."dir.test".hook_point.main.blocks.default]
priority = 1
block = "call-server dir_case;"
[servers.dir_case]
type = "dir"
root_path = "{root}"
""".strip() + "\n",
            )
        gateway = GatewayProcess(sub, config_path, sub / "buckyos-root")
        try:
            gateway.start()
            wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
            status, _, body = http_text(entry_port, "dir.test", "/")
            assert_eq(status, 200, f"{ext} status")
            assert_eq(body, f"DIR-{ext}", f"{ext} body")
        finally:
            gateway.stop()


class StaticConfigServer:
    def __init__(self, content):
        self.content = content.encode("utf-8")
        self.httpd = None
        self.thread = None
        self.port = None

    def start(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("content-type", "application/yaml")
                self.send_header("content-length", str(len(owner.content)))
                self.end_headers()
                self.wfile.write(owner.content)

            def log_message(self, fmt, *args):
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)


def test_config_include_merge_and_remote_cache(case_dir):
    entry_port = free_port()
    root = case_dir / "www"
    write_file(root / "index.html", "REMOTE")
    remote_content = f"""
servers:
  dir.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server dir_case;
  dir_case:
    type: dir
    root_path: {root}
"""
    remote = StaticConfigServer(textwrap.dedent(remote_content).strip() + "\n")
    remote.start()
    config_path = case_dir / "root.yaml"
    write_file(
        config_path,
        f"""
includes:
  - path: http://127.0.0.1:{remote.port}/remote.yaml
stacks:
  entry:
    bind: 127.0.0.1:{entry_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;
servers:
  acme_response:
    type: acme_response
""".strip()
        + "\n",
    )

    for pass_name in ("remote", "cached"):
        gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
        try:
            if pass_name == "cached":
                remote.stop()
            gateway.start()
            wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
            status, _, body = http_text(entry_port, "dir.test", "/")
            assert_eq(status, 200, f"{pass_name} include status")
            assert_eq(body, "REMOTE", f"{pass_name} include body")
        finally:
            gateway.stop()
    remote.stop()


def test_config_local_include_merge_semantics(case_dir):
    config_dir = case_dir / "config"
    include_dir = config_dir / "include.d"
    root_dir = config_dir / "www-main"
    base_dir = config_dir / "www-base"
    extra_dir = config_dir / "www-extra"
    write_file(root_dir / "index.html", "ROOT")
    write_file(base_dir / "index.html", "BASE")
    write_file(extra_dir / "index.html", "EXTRA")
    entry_port = free_port()

    write_file(
        config_dir / "base.yaml",
        f"""
stacks:
  entry:
    bind: 127.0.0.1:{entry_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;
servers:
  merge.test:
    type: http
    gzip: true
    gzip_types:
      - text/plain
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server base_dir;
  base_dir:
    type: dir
    root_path: {base_dir}
""".strip()
        + "\n",
    )
    write_file(
        include_dir / "10-extra.yaml",
        f"""
servers:
  extra.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server extra_dir;
  extra_dir:
    type: dir
    root_path: {extra_dir}
""".strip()
        + "\n",
    )
    config_path = config_dir / "root.yaml"
    write_file(
        config_path,
        f"""
includes:
  - path: base.yaml
  - path: include.d
user_name: app_user
password: app_pass
servers:
  acme_response:
    type: acme_response
  merge.test:
    gzip_types:
      - text/plain
      - text/html
    hook_point:
      main:
        blocks:
          default:
            block: |
              call-server root_dir;
  root_dir:
    type: dir
    root_path: {root_dir}
""".strip()
        + "\n",
    )

    gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        status, _, body = http_text(entry_port, "merge.test", "/")
        assert_eq(status, 200, "local include merged route status")
        assert_eq(body, "ROOT", "root config should override included route")
        status, _, body = http_text(entry_port, "extra.test", "/")
        assert_eq(status, 200, "directory include route status")
        assert_eq(body, "EXTRA", "directory include route body")

        token = control_login(BUILTIN_CONTROL_PORT)
        config = control_rpc(
            BUILTIN_CONTROL_PORT,
            "get_config",
            {"id": "server:merge.test"},
            token=token,
        )["result"]
        assert_eq(config.get("gzip_types"), ["text/plain", "text/html"], "array merge dedupe")
    finally:
        gateway.stop()


def test_config_relative_path_from_main_file(case_dir):
    config_dir = case_dir / "main-config"
    include_dir = config_dir / "nested"
    rel_root = config_dir / "rel-www"
    write_file(rel_root / "index.html", "REL-MAIN")
    entry_port = free_port()
    write_file(
        include_dir / "routes.yaml",
        """
servers:
  rel.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server rel_dir;
  rel_dir:
    type: dir
    root_path: ./rel-www
""".strip()
        + "\n",
    )
    config_path = config_dir / "root.yaml"
    write_file(
        config_path,
        f"""
includes:
  - path: nested/routes.yaml
stacks:
  entry:
    bind: 127.0.0.1:{entry_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;
servers:
  acme_response:
    type: acme_response
""".strip()
        + "\n",
    )
    gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        status, _, body = http_text(entry_port, "rel.test", "/")
        assert_eq(status, 200, "relative path from main config status")
        assert_eq(body, "REL-MAIN", "relative path should resolve from main config dir")
    finally:
        gateway.stop()


def test_invalid_server_type_and_timer_timeout_exit(case_dir):
    for name, config, expected in (
        (
            "bad_server",
            """
stacks: {}
servers:
  bad:
    type: definitely_unknown
""",
            "unknown server type",
        ),
        (
            "bad_timer",
            """
stacks: {}
servers: {}
timers:
  tick:
    timeout: 0
    process_chain: |
      echo "tick";
""",
            "timeout must be greater than 0",
        ),
    ):
        sub = case_dir / name
        config_path = sub / "bad.yaml"
        write_file(config_path, textwrap.dedent(config).strip() + "\n")
        gateway = GatewayProcess(sub, config_path, sub / "buckyos-root")
        try:
            gateway.start()
            try:
                gateway.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                fail(f"{name} process did not exit")
            assert_in(expected, gateway.output(), f"{name} output")
        finally:
            gateway.stop()


def render_control_mutation_config(case_dir, entry_port):
    roots = {}
    for name, body in {
        "fallback": "FALLBACK",
        "set": "SET",
        "insert": "INSERT",
        "add": "ADD",
        "append": "APPEND",
    }.items():
        root = case_dir / "www" / name
        roots[name] = root
        write_file(root / "index.html", body)
        if name != "fallback":
            write_file(root / name, body)

    config = f"""
user_name: app_user
password: app_pass
stacks:
  entry:
    bind: 127.0.0.1:{entry_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;
servers:
  acme_response:
    type: acme_response
  mutate.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server fallback_dir;
  fallback_dir:
    type: dir
    root_path: {roots['fallback']}
  set_dir:
    type: dir
    root_path: {roots['set']}
  insert_dir:
    type: dir
    root_path: {roots['insert']}
  add_dir:
    type: dir
    root_path: {roots['add']}
  append_dir:
    type: dir
    root_path: {roots['append']}
"""
    config_path = case_dir / "cyfs_gateway.yaml"
    write_file(config_path, textwrap.dedent(config).strip() + "\n")
    return config_path


def test_control_rule_mutation_roundtrip(case_dir):
    entry_port = free_port()
    config_path = render_control_mutation_config(case_dir, entry_port)
    gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        token = control_login(BUILTIN_CONTROL_PORT)

        status, _, body = http_text(entry_port, "mutate.test", "/")
        assert_eq(status, 200, "initial mutate route status")
        assert_eq(body, "FALLBACK", "initial mutate route body")

        block_id = "server:mutate.test:hook_point:main:default"
        control_rpc(
            BUILTIN_CONTROL_PORT,
            "set_rule",
            {
                "id": block_id,
                "rule": 'starts-with ${REQ.path} "/set" && call-server set_dir;\ncall-server fallback_dir;',
            },
            token=token,
        )
        status, _, body = http_text(entry_port, "mutate.test", "/set")
        assert_eq(status, 200, "set_rule route status")
        assert_eq(body, "SET", "set_rule route body")

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "insert_rule",
            {
                "id": block_id,
                "pos": "1",
                "rule": 'starts-with ${REQ.path} "/insert" && call-server insert_dir;',
            },
            token=token,
        )
        status, _, body = http_text(entry_port, "mutate.test", "/insert")
        assert_eq(status, 200, "insert_rule route status")
        assert_eq(body, "INSERT", "insert_rule route body")

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "append_rule",
            {
                "id": block_id,
                "rule": 'starts-with ${REQ.path} "/append" && call-server append_dir;',
            },
            token=token,
        )

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "move_rule",
            {"id": f"{block_id}:2", "new_pos": "1"},
            token=token,
        )
        control_rpc(
            BUILTIN_CONTROL_PORT,
            "add_rule",
            {
                "id": block_id,
                "rule": 'starts-with ${REQ.path} "/add" && call-server add_dir;',
            },
            token=token,
        )
        status, _, body = http_text(entry_port, "mutate.test", "/add")
        assert_eq(status, 200, "add_rule route status")
        assert_eq(body, "ADD", "add_rule route body")

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "remove_rule",
            {"id": f"{block_id}:1"},
            token=token,
        )
        status, _, body = http_text(entry_port, "mutate.test", "/add")
        assert_true(status != 200 or body != "ADD", "remove_rule should remove prepended add route")
    finally:
        gateway.stop()


def test_control_router_roundtrip(case_dir):
    entry_port = free_port()
    local_root = case_dir / "router-local"
    write_file(local_root / "index.html", "ROUTER-INDEX")
    write_file(local_root / "exact.txt", "ROUTER-EXACT")
    upstream = UpstreamServer()
    upstream.start()
    config_path = case_dir / "cyfs_gateway.yaml"
    write_file(
        config_path,
        f"""
user_name: app_user
password: app_pass
stacks:
  entry:
    bind: 127.0.0.1:{entry_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;
servers:
  acme_response:
    type: acme_response
""".strip()
        + "\n",
    )
    gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        token = control_login(BUILTIN_CONTROL_PORT)
        server_id = "server:router.test"

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "add_router",
            {"id": server_id, "uri": "=/exact.txt", "target": str(local_root)},
            token=token,
        )
        status, _, body = http_text(entry_port, "router.test", "/exact.txt")
        assert_eq(status, 200, "exact router status")
        assert_eq(body, "ROUTER-EXACT", "exact router body")

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "add_router",
            {"id": server_id, "uri": "/static/*", "target": str(local_root) + "/"},
            token=token,
        )
        status, _, body = http_text(entry_port, "router.test", "/static/index.html")
        assert_eq(status, 200, "wildcard router status")
        assert_eq(body, "ROUTER-INDEX", "wildcard router body")

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "add_router",
            {
                "id": server_id,
                "uri": "~^/rx/(.*)$",
                "target": f"http://127.0.0.1:{upstream.port}/$1",
            },
            token=token,
        )
        status, _, body = http_text(entry_port, "router.test", "/rx/hello")
        assert_eq(status, 200, "regex router status")
        assert_endswith(body, "/hello", "regex router body")

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "remove_router",
            {"id": server_id, "uri": "/static/*", "target": str(local_root) + "/"},
            token=token,
        )
        status, _, body = http_text(entry_port, "router.test", "/static/index.html")
        assert_true(status != 200 or body != "ROUTER-INDEX", "removed router should not match")
    finally:
        gateway.stop()
        upstream.stop()


def test_control_dispatch_roundtrip(case_dir):
    direct_echo = EchoServer()
    udp_echo = UdpEchoServer(prefix=b"DISPATCH:")
    direct_echo.start()
    udp_echo.start()
    tcp_port = free_port()
    udp_port = free_udp_port()
    config_path = case_dir / "cyfs_gateway.yaml"
    write_file(
        config_path,
        """
user_name: app_user
password: app_pass
stacks: {}
servers: {}
""".strip()
        + "\n",
    )
    gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        token = control_login(BUILTIN_CONTROL_PORT)

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "add_dispatch",
            {"local": f"127.0.0.1:{tcp_port}", "target": f"127.0.0.1:{direct_echo.port}"},
            token=token,
        )
        wait_tcp_port(gateway, tcp_port, "tcp dispatch")
        assert_eq(tcp_roundtrip(tcp_port, b"tcp-dispatch"), b"tcp-dispatch", "tcp dispatch echo")

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "add_dispatch",
            {
                "local": f"127.0.0.1:{udp_port}",
                "target": f"127.0.0.1:{udp_echo.port}",
                "protocol": "udp",
            },
            token=token,
        )
        assert_eq(udp_roundtrip(udp_port, b"udp"), b"DISPATCH:udp", "udp dispatch echo")

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "remove_dispatch",
            {"local": f"127.0.0.1:{tcp_port}"},
            token=token,
        )
        assert_tcp_connect_fails(tcp_port, "tcp dispatch still accepted after remove")

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "remove_dispatch",
            {"local": f"127.0.0.1:{udp_port}", "protocol": "udp"},
            token=token,
        )
    finally:
        gateway.stop()
        direct_echo.stop()
        udp_echo.stop()


def test_control_api_surface_roundtrip(case_dir):
    config_path = case_dir / "cyfs_gateway.yaml"
    buckyos_root = case_dir / "buckyos-root"
    template_port = free_port()
    template_root = case_dir / "template-root"
    save_path = case_dir / "saved-config.json"
    write_file(template_root / "index.html", "CONTROL-TEMPLATE")
    install_control_test_template(buckyos_root)
    write_file(
        config_path,
        """
user_name: app_user
password: app_pass
collections:
  app_set:
    type: memory_set
  app_map:
    type: memory_map
stacks: {}
servers: {}
""".strip()
        + "\n",
    )
    gateway = GatewayProcess(case_dir, config_path, buckyos_root)
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        token = control_login(BUILTIN_CONTROL_PORT)

        system_info = control_rpc(
            BUILTIN_CONTROL_PORT,
            "get_system_info",
            {"dashboard_port": 12345},
            token=token,
        )["result"]
        assert_eq(system_info.get("ui_mode"), "developer", "control get_system_info ui_mode")
        assert_true(
            isinstance(system_info.get("dashboard", {}).get("port"), int),
            "control get_system_info dashboard port type",
        )

        config = control_rpc(BUILTIN_CONTROL_PORT, "get_config", None, token=token)["result"]
        assert_true("stacks" in config, "control get_config missing stacks")
        init_config = control_rpc(BUILTIN_CONTROL_PORT, "get_init_config", None, token=token)[
            "result"
        ]
        assert_true("collections" in init_config, "control get_init_config missing collections")

        saved = control_rpc(
            BUILTIN_CONTROL_PORT,
            "save_config",
            {"config": str(save_path)},
            token=token,
        )["result"]
        assert_eq(saved, str(save_path), "control save_config path")
        assert_true(save_path.exists(), "control save_config did not write file")

        connections = control_rpc(BUILTIN_CONTROL_PORT, "get_connections", None, token=token)[
            "result"
        ]
        devices = control_rpc(
            BUILTIN_CONTROL_PORT,
            "get_connection_devices",
            None,
            token=token,
        )["result"]
        assert_true(isinstance(connections, list), "control get_connections result type")
        assert_true(isinstance(devices, list), "control get_connection_devices result type")

        tunnel_params = {
            "urls": ["udp://127.0.0.1:9/", "unknown://127.0.0.1:9/"],
            "sort": "reachable_first",
            "include_unsupported": False,
        }
        for method in ("query_tunnel_url_statuses", "tunnels_probe", "/tunnels/probe"):
            probe = control_rpc(BUILTIN_CONTROL_PORT, method, tunnel_params, token=token)["result"]
            assert_true("statuses" in probe, f"control {method} missing statuses")
            assert_true("sorted_urls" in probe, f"control {method} missing sorted_urls")

        for method, trust_level in (("add_name_provider", 101), ("add-name-provider", 102)):
            provider = control_rpc(
                BUILTIN_CONTROL_PORT,
                method,
                {"url": f"http://127.0.0.1:{free_port()}", "trust_level": trust_level},
                token=token,
            )["result"]
            assert_eq(provider.get("scheme"), "http", f"control {method} scheme")
            assert_eq(provider.get("trust_level"), trust_level, f"control {method} trust")

        cmds = control_rpc(BUILTIN_CONTROL_PORT, "external_cmds", None, token=token)["result"]
        assert_true(
            any(cmd.get("name") == "control_test" for cmd in cmds),
            "control external_cmds missing control_test",
        )
        help_text = control_rpc(
            BUILTIN_CONTROL_PORT,
            "cmd_help",
            {"cmd": "control_test"},
            token=token,
        )["result"]
        assert_in("control_test", help_text, "control cmd_help")

        started = control_rpc(
            BUILTIN_CONTROL_PORT,
            "start",
            {
                "template_id": "control_test",
                "args": ["--bind", f"127.0.0.1:{template_port}", "--path", str(template_root)],
            },
            token=token,
        )["result"]
        assert_true("stacks" in started, "control start result missing stacks")
        wait_tcp_port(gateway, template_port, "control start template")
        status, _, body = http_text(template_port, "control.test", "/")
        assert_eq(status, 200, "control start template status")
        assert_eq(body, "CONTROL-TEMPLATE", "control start template body")

        invalid = control_rpc_raw(BUILTIN_CONTROL_PORT, "missing_control_method", None, token=token)
        assert_eq(invalid["status"], 200, "control invalid method http status")
        assert_true(
            invalid["data"].get("error") is not None,
            "control invalid method should return rpc error",
        )
    finally:
        gateway.stop()


def test_control_collection_roundtrip(case_dir):
    config_path = case_dir / "cyfs_gateway.yaml"
    write_file(
        config_path,
        """
user_name: app_user
password: app_pass
collections:
  app_set:
    type: memory_set
  app_map:
    type: memory_map
stacks: {}
servers: {}
""".strip()
        + "\n",
    )
    gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        token = control_login(BUILTIN_CONTROL_PORT)
        listing = control_rpc(BUILTIN_CONTROL_PORT, "collection_list", None, token=token)["result"]
        assert_true(
            any(item.get("name") == "app_set" and item.get("type") == "set" for item in listing),
            "collection list missing app_set",
        )
        assert_true(
            any(item.get("name") == "app_map" and item.get("type") == "map" for item in listing),
            "collection list missing app_map",
        )

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "collection_set_add",
            {"name": "app_set", "value": "alpha"},
            token=token,
        )
        set_state = control_rpc(
            BUILTIN_CONTROL_PORT,
            "collection_get",
            {"name": "app_set"},
            token=token,
        )["result"]
        assert_in("alpha", set_state.get("items", []), "collection set-add")

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "collection_set_del",
            {"name": "app_set", "value": "alpha"},
            token=token,
        )
        set_state = control_rpc(
            BUILTIN_CONTROL_PORT,
            "collection_get",
            {"name": "app_set"},
            token=token,
        )["result"]
        assert_not_in("alpha", set_state.get("items", []), "collection set-del")

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "collection_map_put",
            {"name": "app_map", "key": "k1", "value": "v1"},
            token=token,
        )
        map_value = control_rpc(
            BUILTIN_CONTROL_PORT,
            "collection_get",
            {"name": "app_map", "key": "k1"},
            token=token,
        )["result"]
        assert_eq(map_value.get("value"), "v1", "collection map-put")

        control_rpc(
            BUILTIN_CONTROL_PORT,
            "collection_map_del",
            {"name": "app_map", "key": "k1"},
            token=token,
        )
        map_value = control_rpc(
            BUILTIN_CONTROL_PORT,
            "collection_get",
            {"name": "app_map", "key": "k1"},
            token=token,
        )["result"]
        assert_true(map_value.get("value") is None, "collection map-del")
    finally:
        gateway.stop()


def test_http_dir_server_options(case_dir):
    entry_port = free_port()
    root = case_dir / "dir-options"
    write_file(root / "home.html", "HOME")
    write_file(root / "fallback.html", "FALLBACK-FILE")
    write_file(root / "etag.txt", "ETAG-BODY")
    write_file(root / "list" / "item.txt", "LIST-ITEM")
    config_path = case_dir / "cyfs_gateway.yaml"
    write_file(
        config_path,
        f"""
stacks:
  entry:
    bind: 127.0.0.1:{entry_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;
servers:
  acme_response:
    type: acme_response
  dir-options.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server dir_options;
  dir_options:
    type: dir
    root_path: {root}
    index_file: home.html
    fallback_file: fallback.html
    autoindex: true
    etag: true
    if_modified_since: exact
""".strip()
        + "\n",
    )
    gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        status, _, body = http_text(entry_port, "dir-options.test", "/")
        assert_eq(status, 200, "custom index status")
        assert_eq(body, "HOME", "custom index body")

        status, _, body = http_text(entry_port, "dir-options.test", "/missing")
        assert_eq(status, 200, "fallback file status")
        assert_eq(body, "FALLBACK-FILE", "fallback file body")

        status, headers, body = http_text(entry_port, "dir-options.test", "/etag.txt")
        assert_eq(status, 200, "etag initial status")
        assert_eq(body, "ETAG-BODY", "etag initial body")
        etag = headers.get("etag")
        assert_true(etag is not None, "etag header should exist")
        status, _, body = http_text(
            entry_port,
            "dir-options.test",
            "/etag.txt",
            headers={"If-None-Match": etag},
        )
        assert_eq(status, 304, "if-none-match status")
        assert_eq(body, "", "if-none-match body")

        status, _, body = http_text(entry_port, "dir-options.test", "/list/")
        assert_eq(status, 200, "autoindex status")
        assert_in("item.txt", body, "autoindex listing")
    finally:
        gateway.stop()


def test_http_compression_options(case_dir):
    entry_port = free_port()
    root = case_dir / "compression"
    write_file(root / "big.txt", "big-body-" * 80)
    write_file(root / "small.txt", "small")
    config_path = case_dir / "cyfs_gateway.yaml"
    write_file(
        config_path,
        f"""
stacks:
  entry:
    bind: 127.0.0.1:{entry_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;
servers:
  acme_response:
    type: acme_response
  compress.test:
    type: http
    gzip: true
    gzip_vary: true
    gzip_min_length: 32
    gzip_types:
      - text/plain
    brotli: true
    brotli_min_length: 32
    brotli_types:
      - text/plain
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server compress_dir;
  compress_dir:
    type: dir
    root_path: {root}
""".strip()
        + "\n",
    )
    gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        status, headers, body = http_request(
            entry_port,
            "compress.test",
            "/big.txt",
            headers={"Accept-Encoding": "gzip"},
        )
        assert_eq(status, 200, "gzip big status")
        assert_eq(headers.get("content-encoding"), "gzip", "gzip big encoding")
        assert_eq(headers.get("vary"), "Accept-Encoding", "gzip vary")
        assert_in("big-body-", gzip.decompress(body).decode("utf-8"), "gzip big body")

        status, headers, body = http_text(
            entry_port,
            "compress.test",
            "/small.txt",
            headers={"Accept-Encoding": "gzip"},
        )
        assert_eq(status, 200, "gzip small status")
        assert_true("content-encoding" not in headers, "small response should not be gzip")
        assert_eq(body, "small", "gzip min length body")

        status, headers, _ = http_request(
            entry_port,
            "compress.test",
            "/big.txt",
            headers={"Accept-Encoding": "br"},
        )
        assert_eq(status, 200, "brotli status")
        assert_eq(headers.get("content-encoding"), "br", "brotli encoding")
    finally:
        gateway.stop()


def test_gateway_external_commands_runtime(case_dir):
    entry_port = free_port()
    root = case_dir / "external-cmds"
    cookie_root = case_dir / "external-cookie"
    num_root = case_dir / "external-num"
    write_file(root / "index.html", "EXTERNAL-FALLBACK")
    write_file(cookie_root / "index.html", "COOKIE-OK")
    write_file(cookie_root / "cookie", "COOKIE-OK")
    write_file(num_root / "index.html", "NUM-OK")
    write_file(num_root / "num", "NUM-OK")
    config_path = case_dir / "cyfs_gateway.yaml"
    write_file(
        config_path,
        f"""
stacks:
  entry:
    bind: 127.0.0.1:{entry_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;
servers:
  acme_response:
    type: acme_response
  external.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              if starts-with ${{REQ.path}} "/error" then
                return "error 418 \\\"teapot\\\"";
              elif starts-with ${{REQ.path}} "/redirect" then
                return "redirect https://example.com/login 307";
              elif starts-with ${{REQ.path}} "/cookie" then
                local cookie=$(parse-cookie $REQ.Cookie);
                eq $cookie.sid "abc" && call-server cookie_dir;
                return "error 400 \\\"bad cookie\\\"";
              elif starts-with ${{REQ.path}} "/num" then
                num-cmp "10" gt "2" && call-server num_dir;
                return "error 400 \\\"bad num\\\"";
              else
                call-server external_dir;
              end
  external_dir:
    type: dir
    root_path: {root}
  cookie_dir:
    type: dir
    root_path: {cookie_root}
  num_dir:
    type: dir
    root_path: {num_root}
""".strip()
        + "\n",
    )
    gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        status, _, body = http_text(entry_port, "external.test", "/error")
        assert_eq(status, 418, "error command status")
        assert_in("teapot", body, "error command body")

        status, headers, _ = http_request(entry_port, "external.test", "/redirect")
        assert_eq(status, 307, "redirect command status")
        assert_eq(headers.get("location"), "https://example.com/login", "redirect location")

        status, _, body = http_text(
            entry_port,
            "external.test",
            "/cookie",
            headers={"Cookie": "sid=abc; theme=dark"},
        )
        assert_eq(status, 200, "parse-cookie command status")
        assert_eq(body, "COOKIE-OK", "parse-cookie response body")

        status, _, body = http_text(entry_port, "external.test", "/num")
        assert_eq(status, 200, "num-cmp command status")
        assert_eq(body, "NUM-OK", "num-cmp response body")
    finally:
        gateway.stop()


def test_dns_socks_control_token_edges(case_dir):
    resources = start_full_gateway(case_dir)
    gateway, _upstream, direct_echo, _proxy_echo, ports, _dump_file = resources
    try:
        addrs = dns_query_a(ports["dns"], "www.buckyos.com")
        assert_eq(addrs, ["192.168.1.1"], "dns configured A record")
        missing = dns_query(ports["dns"], "missing.buckyos.com")
        assert_eq(missing["records"], [], "dns missing record answers")

        with socks5_connect_domain(
            ports["socks"], "gateway_user", "gateway_pass", "localhost", direct_echo.port
        ) as s:
            s.sendall(b"socks-domain")
            assert_eq(s.recv(64), b"socks-domain", "socks domain echo")
        assert_socks_auth_fails(ports["socks"], "gateway_user", "wrong_pass")

        no_token = control_rpc_raw(ports["control"], "get_config", None)
        assert_true(
            no_token["status"] == 401
            or (no_token["data"] or {}).get("error") is not None,
            "control get_config without token should fail",
        )
        bad_token = control_rpc_raw(ports["control"], "get_config", None, token="bad-token")
        assert_true(
            bad_token["status"] == 401
            or (bad_token["data"] or {}).get("error") is not None,
            "control get_config with bad token should fail",
        )
    finally:
        stop_full_gateway(resources)


def test_acme_response_unknown_token(case_dir):
    entry_port = free_port()
    config_path = case_dir / "cyfs_gateway.yaml"
    write_file(
        config_path,
        f"""
stacks:
  entry:
    bind: 127.0.0.1:{entry_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server acme_host;
              reject;
servers:
  acme_response:
    type: acme_response
  acme_host:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              starts-with ${{REQ.path}} "/.well-known/acme-challenge/" && call-server acme_response;
              return "error 404";
""".strip()
        + "\n",
    )
    gateway = GatewayProcess(case_dir, config_path, case_dir / "buckyos-root")
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        status, _, body = http_text(
            entry_port, "acme.test", "/.well-known/acme-challenge/not-present"
        )
        assert_eq(status, 404, "acme unknown token status")
        assert_true("not found" in body.lower() or body == "", "acme unknown token body")
    finally:
        gateway.stop()


def test_timer_and_json_set_persistence(case_dir):
    entry_port = free_port()
    set_file = case_dir / "persist_set.json"
    config_path = case_dir / "cyfs_gateway.yaml"
    write_file(
        config_path,
        f"""
user_name: app_user
password: app_pass
collections:
  persist_set:
    type: json_set
    file_path: {set_file}
timers:
  tick:
    timeout: 1
    process-chain: |
      set-add persist_set "timer-hit";
stacks:
  entry:
    bind: 127.0.0.1:{entry_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              reject;
servers:
  acme_response:
    type: acme_response
""".strip()
        + "\n",
    )
    root = case_dir / "buckyos-root"
    gateway = GatewayProcess(case_dir, config_path, root)
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        token = control_login(BUILTIN_CONTROL_PORT)
        deadline = time.monotonic() + 5
        seen = False
        while time.monotonic() < deadline:
            state = control_rpc(
                BUILTIN_CONTROL_PORT, "collection_get", {"name": "persist_set"}, token=token
            )["result"]
            if "timer-hit" in state.get("items", []):
                seen = True
                break
            time.sleep(0.25)
        assert_true(seen, "timer should update json_set collection")
    finally:
        gateway.stop()

    gateway = GatewayProcess(case_dir, config_path, root)
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        token = control_login(BUILTIN_CONTROL_PORT)
        state = control_rpc(
            BUILTIN_CONTROL_PORT, "collection_get", {"name": "persist_set"}, token=token
        )["result"]
        assert_in("timer-hit", state.get("items", []), "json_set should persist across restart")
    finally:
        gateway.stop()


def test_tls_stack_self_cert_http_smoke(case_dir):
    tls_port = free_port()
    root = case_dir / "tls-www"
    buckyos_root = case_dir / "buckyos-root"
    write_file(root / "index.html", "TLS-OK")
    install_tls_identity_cert(buckyos_root, "tls.test")
    config_path = case_dir / "cyfs_gateway.yaml"
    write_file(
        config_path,
        f"""
stacks:
  tls_entry:
    bind: 127.0.0.1:{tls_port}
    protocol: tls
    hosts:
      - tls.test
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server ${{REQ.dest_host}};
              reject;
servers:
  acme_response:
    type: acme_response
  tls.test:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server tls_dir;
  tls_dir:
    type: dir
    root_path: {root}
""".strip()
        + "\n",
    )
    gateway = GatewayProcess(case_dir, config_path, buckyos_root)
    try:
        gateway.start()
        wait_gateway_ready(gateway, BUILTIN_CONTROL_PORT)
        wait_tcp_port(gateway, tls_port, "tls stack")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", tls_port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname="tls.test") as sock:
                sock.settimeout(5)
                sock.sendall(
                    b"GET / HTTP/1.1\r\nHost: tls.test\r\nConnection: close\r\n\r\n"
                )
                chunks = []
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
        response = b"".join(chunks)
        assert_in(b"200 OK", response, "tls http status")
        assert_in(b"TLS-OK", response, "tls http body")
    finally:
        gateway.stop()


CASES = [
    ("minimal_startup_and_dir_routing", test_minimal_startup_and_dir_routing),
    ("process_chain_runtime_routes", test_process_chain_runtime_routes),
    ("full_process_chain_runtime", test_full_process_chain_runtime),
    ("gzip_dns_socks_and_proxy_protocol", test_gzip_dns_socks_and_proxy_protocol),
    ("reload_runtime_workloads", test_reload_runtime_workloads),
    ("multi_gateway_tunnel_protocols", test_multi_gateway_tunnel_protocols),
    ("rtcp_app_tunnel_roundtrip", test_rtcp_app_tunnel_roundtrip),
    (
        "rtcp_app_tunnel_roundtrip_with_remote_keep_tunnel_ropen",
        test_rtcp_app_tunnel_roundtrip_with_remote_keep_tunnel_ropen,
    ),
    (
        "rtcp_app_tunnel_roundtrip_with_remote_keep_tunnel",
        test_rtcp_app_tunnel_roundtrip_with_remote_keep_tunnel,
    ),
    (
        "rtcp_app_tunnel_roundtrip_with_client_http_stack_forward",
        test_rtcp_app_tunnel_roundtrip_with_client_http_stack_forward,
    ),
    (
        "rtcp_app_tunnel_roundtrip_with_client_http_stack_forward_and_remote_keep_tunnel",
        test_rtcp_app_tunnel_roundtrip_with_client_http_stack_forward_and_remote_keep_tunnel,
    ),
    (
        "buckyos_config_gen_web3_exported_http_reaches_node",
        test_buckyos_config_gen_web3_exported_http_reaches_node,
    ),
    ("cli_against_running_app", test_cli_against_running_app),
    ("config_loading_formats_and_paths", test_config_loading_formats_and_paths),
    ("config_include_merge_and_remote_cache", test_config_include_merge_and_remote_cache),
    ("config_local_include_merge_semantics", test_config_local_include_merge_semantics),
    ("config_relative_path_from_main_file", test_config_relative_path_from_main_file),
    ("invalid_config_exits", test_invalid_config_exits),
    ("invalid_server_type_and_timer_timeout_exit", test_invalid_server_type_and_timer_timeout_exit),
    ("control_rule_mutation_roundtrip", test_control_rule_mutation_roundtrip),
    ("control_router_roundtrip", test_control_router_roundtrip),
    ("control_dispatch_roundtrip", test_control_dispatch_roundtrip),
    ("control_api_surface_roundtrip", test_control_api_surface_roundtrip),
    ("control_collection_roundtrip", test_control_collection_roundtrip),
    ("http_dir_server_options", test_http_dir_server_options),
    ("http_compression_options", test_http_compression_options),
    ("gateway_external_commands_runtime", test_gateway_external_commands_runtime),
    ("dns_socks_control_token_edges", test_dns_socks_control_token_edges),
    ("acme_response_unknown_token", test_acme_response_unknown_token),
    ("timer_and_json_set_persistence", test_timer_and_json_set_persistence),
    ("tls_stack_self_cert_http_smoke", test_tls_stack_self_cert_http_smoke),
    ("cli_help_and_gen_rtcp_key", test_cli_help_and_gen_rtcp_key),
]


def main():
    build_gateway()
    failed = 0
    for name, case in CASES:
        try:
            run_gateway_case(name, case)
        except Exception as exc:
            failed += 1
            print(f"[cyfs-gateway-app] case failed: {name}: {exc}", file=sys.stderr)
    if failed:
        print(f"[cyfs-gateway-app] failed={failed}", file=sys.stderr)
        return 1
    print("[cyfs-gateway-app] all cases passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
