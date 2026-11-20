#!/usr/bin/env python3
"""End-to-end data-transfer probe for each of the 6 VPN routes
(Reality/Hysteria2/XHTTP x Rifty/Adminor).

Unlike check-host.net (raw TCP/HTTP reachability to an IP, no protocol
awareness) this actually speaks the real protocol through a pinned,
single-outbound client config -- no balancer, no observatory, exactly one
route per run -- and downloads a known 256 KiB file from a host
independent of both VPN nodes (GitHub raw), verifying size + SHA-256.

Usage:
  python3 route_probe.py --config nodes_probe.json --route reality_exit
  python3 route_probe.py --config nodes_probe.json --all --tag home
  python3 route_probe.py --config nodes_probe.json --all --tag mobile --report-via-ssh

Writes results as JSON to stdout and, if --out is given, to that file:
  {"route": {"status": "ok"|"error"|"unknown", "stage": "...",
             "bytes": N, "ts": unix_ts}, ...}

Binaries (xray, hysteria client) are located via --xray-bin/--hysteria-bin
or the XRAY_BIN/HYSTERIA_BIN env vars -- there is no single bundled path
since this script runs on different machines (Rifty for dev/testing, a
home router, or the operator's own laptop for an on-demand mobile-network
check) with different binaries already in place.
"""
import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TEST_FILE_URL = "https://raw.githubusercontent.com/Algeron1/vpn-route-probe-asset/main/probe-blob.bin"
TEST_FILE_SHA256 = "5d89c0ff8550e1da00ec3504f630616e37c071c919c6f00aea422a2d4ac8c0e4"
TEST_FILE_SIZE = 262144

XRAY_BIN = os.environ.get("XRAY_BIN", "xray")
HYSTERIA_BIN = os.environ.get("HYSTERIA_BIN", "hysteria")
# Hysteria2 userpass auth is "username:password" -- which username depends on
# which vantage point's dedicated test client this run uses (e.g. "_probe_test"
# on Rifty itself, "_probe_home" on the home router); a wrong-but-plausible
# username with the right password gets rejected and looks like a dead route
# (confirmed 2026-11-20, found via the home router using _probe_home creds
# against a hardcoded "_probe_test" login).
PROBE_NAME = os.environ.get("PROBE_NAME", "_probe_test")


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def build_xray_reality_config(socks_port: int, node: dict, uuid: str) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": node["ip"], "port": node["port"],
                "users": [{"id": uuid, "encryption": "none", "flow": node.get("flow", "")}],
            }]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "publicKey": node["pubkey"],
                    "fingerprint": node.get("fingerprint", "firefox"),
                    "serverName": node["dest"],
                    "shortId": node["short_id"],
                },
            },
        }],
    }


def build_xray_xhttp_config(socks_port: int, node: dict, uuid: str) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": node["domain"], "port": node["port"],
                "users": [{"id": uuid, "encryption": "none", "flow": ""}],
            }]},
            "streamSettings": {
                "network": "xhttp", "security": "tls",
                "tlsSettings": {"serverName": node["domain"], "fingerprint": "chrome", "alpn": ["h2", "http/1.1"]},
                "xhttpSettings": {"path": node["path"], "host": node["domain"], "mode": "packet-up"},
            },
        }],
    }


def build_hysteria_client_config(socks_port: int, node: dict, password: str) -> dict:
    # Hysteria2 userpass auth takes "username:password" as a single string,
    # same as the userinfo part of a hysteria2:// URI -- a bare password
    # gets rejected by the server with a generic HTTP 404 (confirmed
    # 2026-11-20, see build_hysteria2_link's f"{name}:{uid}" pattern).
    cfg = {
        "server": f"{node['domain']}:{node['port']}",
        "auth": f"{PROBE_NAME}:{password}",
        "socks5": {"listen": f"127.0.0.1:{socks_port}"},
    }
    if node.get("obfs_password"):
        cfg["obfs"] = {"type": "salamander", "salamander": {"password": node["obfs_password"]}}
    return cfg


def spawn_xray(config: dict, workdir: Path):
    cfg_path = workdir / "config.json"
    cfg_path.write_text(json.dumps(config))
    err_path = workdir / "client.stderr"
    proc = subprocess.Popen(
        [XRAY_BIN, "run", "-config", str(cfg_path)],
        stdout=subprocess.DEVNULL, stderr=open(err_path, "wb"),
        start_new_session=True,
    )
    proc.err_path = err_path
    return proc


def _hysteria_yaml(config: dict) -> str:
    """Hand-written YAML for the one shape build_hysteria_client_config
    produces -- avoids a PyYAML dependency on every machine this runs on
    (Rifty, the home router's Entware, the operator's own laptop)."""
    lines = [f"server: {config['server']}", f"auth: {config['auth']}"]
    if "obfs" in config:
        lines += [
            "obfs:", "  type: salamander", "  salamander:",
            f"    password: {config['obfs']['salamander']['password']}",
        ]
    lines += ["socks5:", f"  listen: {config['socks5']['listen']}"]
    return "\n".join(lines) + "\n"


def spawn_hysteria(config: dict, workdir: Path):
    cfg_path = workdir / "hysteria.yaml"
    cfg_path.write_text(_hysteria_yaml(config))
    err_path = workdir / "client.stderr"
    proc = subprocess.Popen(
        [HYSTERIA_BIN, "client", "-c", str(cfg_path)],
        stdout=subprocess.DEVNULL, stderr=open(err_path, "wb"),
        start_new_session=True,
    )
    proc.err_path = err_path
    return proc


def kill_proc(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass


def download_via_socks(socks_port: int, timeout: float = 15.0) -> dict:
    """Returns {"stage": ..., "bytes": N} and raises only on setup errors;
    a failed/partial download is reported via the dict, not an exception,
    so the caller always gets a stage + byte count."""
    # Shell out to curl --socks5-hostname rather than depending on PySocks --
    # curl is already present everywhere this script runs and handles the
    # SOCKS5 handshake + TLS/SNI to the target correctly on its own.
    import shutil
    curl_bin = shutil.which("curl")
    if not curl_bin:
        return {"stage": "no_curl", "bytes": 0}

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name
    try:
        proc = subprocess.run(
            [
                curl_bin, "-s", "-o", tmp_path, "-w", "%{http_code}",
                "--socks5-hostname", f"127.0.0.1:{socks_port}",
                "--max-time", str(timeout),
                TEST_FILE_URL,
            ],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        http_code = proc.stdout.strip()
        size = os.path.getsize(tmp_path) if os.path.exists(tmp_path) else 0
        if proc.returncode != 0:
            stage = {
                5: "socks_proxy_unreachable", 7: "connect_failed",
                28: "timeout", 35: "tls_handshake", 52: "empty_reply",
                56: "recv_failed",
            }.get(proc.returncode, f"curl_errno_{proc.returncode}")
            return {"stage": stage, "bytes": size}
        if http_code != "200":
            return {"stage": f"http_{http_code}", "bytes": size}
        if size != TEST_FILE_SIZE:
            return {"stage": "partial_body", "bytes": size}
        digest = hashlib.sha256(Path(tmp_path).read_bytes()).hexdigest()
        if digest != TEST_FILE_SHA256:
            return {"stage": "hash_mismatch", "bytes": size}
        return {"stage": "ok", "bytes": size}
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


ROUTE_BUILDERS = {
    "reality_exit": ("xray", build_xray_reality_config, "nodes.exit", "reality_exit_uuid"),
    "reality_adminor": ("xray", build_xray_reality_config, "nodes.adminor", "reality_adminor_uuid"),
    "xhttp_exit": ("xray", build_xray_xhttp_config, "cdn_nodes.exit", "xhttp_exit_uuid"),
    "xhttp_adminor": ("xray", build_xray_xhttp_config, "cdn_nodes.adminor", "xhttp_adminor_uuid"),
    "hy2_exit": ("hysteria", build_hysteria_client_config, "hy2_nodes.exit", "hy2_exit_password"),
    "hy2_adminor": ("hysteria", build_hysteria_client_config, "hy2_nodes.adminor", "hy2_adminor_password"),
}


def resolve_path(config: dict, dotted: str):
    node = config
    for part in dotted.split("."):
        node = node[part]
    return node


def wait_for_socks(proc, socks_port: int, timeout: float = 8.0) -> str:
    """Poll until the client's local SOCKS5 port accepts a connection, the
    client process dies, or timeout elapses. A fixed sleep before checking
    doesn't work for Hysteria2 -- its client only opens the SOCKS5 listener
    *after* the QUIC handshake completes (unlike Xray's SOCKS inbound, which
    binds immediately regardless of outbound state), so a slow handshake was
    being misread as a dead route (confirmed 2026-11-20, found via the home
    router: Reality/XHTTP always passed, Hysteria2 failed with
    "connect_failed" even though the server itself was reachable)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return "client_process_died"
        try:
            with socket.create_connection(("127.0.0.1", socks_port), timeout=0.5):
                return "ready"
        except OSError:
            time.sleep(0.2)
    return "socks_not_ready"


def probe_route(route_name: str, vpn_config: dict, secrets: dict) -> dict:
    kind, builder, node_path, secret_key = ROUTE_BUILDERS[route_name]
    try:
        node = resolve_path(vpn_config, node_path)
    except KeyError:
        return {"status": "unknown", "stage": "node_not_configured", "bytes": 0, "ts": int(time.time())}
    secret = secrets.get(secret_key)
    if not secret:
        return {"status": "unknown", "stage": "no_test_credential", "bytes": 0, "ts": int(time.time())}

    socks_port = free_port()
    client_config = builder(socks_port, node, secret)

    with tempfile.TemporaryDirectory() as workdir:
        workdir = Path(workdir)
        proc = spawn_xray(client_config, workdir) if kind == "xray" else spawn_hysteria(client_config, workdir)
        try:
            ready = wait_for_socks(proc, socks_port)
            if ready != "ready":
                detail = ""
                try:
                    detail = proc.err_path.read_text(errors="replace").strip()[-300:]
                except Exception:
                    pass
                return {"status": "error", "stage": ready, "bytes": 0, "ts": int(time.time()), "detail": detail}
            result = download_via_socks(socks_port)
        finally:
            kill_proc(proc)

    status = "ok" if result["stage"] == "ok" else "error"
    out = {"status": status, "stage": result["stage"], "bytes": result["bytes"], "ts": int(time.time())}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="path to a JSON file with the VPN nodes config (config.json shape)")
    ap.add_argument("--secrets", required=True, help="path to probe_secrets.json")
    ap.add_argument("--route", choices=list(ROUTE_BUILDERS), help="probe a single route")
    ap.add_argument("--all", action="store_true", help="probe all 6 routes")
    ap.add_argument("--tag", default="unknown", help="label for this vantage point, e.g. home/mobile")
    ap.add_argument("--out", help="write JSON result to this file instead of only stdout")
    args = ap.parse_args()

    vpn_config = json.loads(Path(args.config).read_text())
    secrets = json.loads(Path(args.secrets).read_text())

    routes = list(ROUTE_BUILDERS) if args.all else [args.route]
    if not routes or routes == [None]:
        print("specify --route <name> or --all", file=sys.stderr)
        return 1

    results = {}
    for route_name in routes:
        results[route_name] = probe_route(route_name, vpn_config, secrets)
        r = results[route_name]
        print(f"{route_name}: {r['status']} ({r['stage']}, {r['bytes']} bytes)", file=sys.stderr)
        if r.get("detail"):
            print(f"  detail: {r['detail']}", file=sys.stderr)

    out = {"tag": args.tag, "ts": int(time.time()), "routes": results}
    print(json.dumps(out, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
