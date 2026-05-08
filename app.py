from __future__ import annotations

import json
import os
import re
import shutil
import socket
import statistics
import subprocess
import threading
import time
from collections import deque
from typing import Any, Sequence

from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

DEFAULT_CONFIG: dict[str, Any] = {
    "bind_host": "0.0.0.0",
    "port": 5088,
    "speed_interval_seconds": 1.0,
    "health_interval_seconds": 5.0,
    "history_limit": 120,
    "quality_window": 20,
    "internet_test_ips": ["1.1.1.1", "8.8.8.8"],
    "internet_test_targets_global": None,
    "internet_test_targets_ir": None,
    "nft_table_family": "inet",
    "nft_table_name": "wanmon",
    "wans": {},
}


def load_config(path: str) -> tuple[dict[str, Any], str | None]:
    if not os.path.exists(path):
        cfg = {
            **DEFAULT_CONFIG,
            "internet_test_ips": list(DEFAULT_CONFIG["internet_test_ips"]),
            "wans": {},
        }
        return cfg, f"Config not found: {path} (copy config.example.json -> config.json)"

    try:
        with open(path, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
    except (OSError, json.JSONDecodeError) as ex:
        cfg = {
            **DEFAULT_CONFIG,
            "internet_test_ips": list(DEFAULT_CONFIG["internet_test_ips"]),
            "wans": {},
        }
        return cfg, f"Config read error: {ex}"

    if not isinstance(user_cfg, dict):
        cfg = {
            **DEFAULT_CONFIG,
            "internet_test_ips": list(DEFAULT_CONFIG["internet_test_ips"]),
            "wans": {},
        }
        return cfg, "Config root must be a JSON object"

    cfg: dict[str, Any] = {
        **DEFAULT_CONFIG,
        "internet_test_ips": list(DEFAULT_CONFIG["internet_test_ips"]),
        "wans": {},
    }

    for key in (
        "bind_host",
        "port",
        "speed_interval_seconds",
        "health_interval_seconds",
        "history_limit",
        "quality_window",
        "internet_test_ips",
        "internet_test_targets_global",
        "internet_test_targets_ir",
        "nft_table_family",
        "nft_table_name",
    ):
        if key in user_cfg:
            cfg[key] = user_cfg[key]

    wans = user_cfg.get("wans", {})
    if not isinstance(wans, dict):
        return cfg, "Config key 'wans' must be an object (mapping wan_id -> settings)"

    errors: list[str] = []
    normalized_wans: dict[str, dict[str, Any]] = {}

    required_keys = {"name", "source_ip", "gateway", "metric", "upload_counter", "download_counter"}

    for wan_id, wan in wans.items():
        if not isinstance(wan_id, str) or not wan_id.strip():
            errors.append("WAN id must be a non-empty string")
            continue

        if not isinstance(wan, dict):
            errors.append(f"WAN '{wan_id}' must be an object")
            continue

        missing = [k for k in required_keys if k not in wan]
        if missing:
            errors.append(f"WAN '{wan_id}' missing keys: {', '.join(sorted(missing))}")
            continue

        try:
            wan_metric = int(wan.get("metric"))
        except (TypeError, ValueError):
            errors.append(f"WAN '{wan_id}' metric must be an integer")
            continue

        normalized_wans[wan_id] = {
            "name": str(wan.get("name", "")),
            "source_ip": str(wan.get("source_ip", "")),
            "gateway": str(wan.get("gateway", "")),
            "metric": wan_metric,
            "upload_counter": str(wan.get("upload_counter", "")),
            "download_counter": str(wan.get("download_counter", "")),
        }

    cfg["wans"] = normalized_wans

    if errors:
        return cfg, "Config errors: " + "; ".join(errors)

    return cfg, None


CONFIG_PATH = os.environ.get("WAN_PANEL_CONFIG") or DEFAULT_CONFIG_PATH
CONFIG, startup_error = load_config(CONFIG_PATH)

BIND_HOST = str(CONFIG.get("bind_host") or "0.0.0.0")
PORT = int(CONFIG.get("port") or 5088)

SPEED_INTERVAL_SECONDS = float(CONFIG.get("speed_interval_seconds") or 1.0)
HEALTH_INTERVAL_SECONDS = float(CONFIG.get("health_interval_seconds") or 5.0)
HISTORY_LIMIT = int(CONFIG.get("history_limit") or 120)

QUALITY_WINDOW = int(CONFIG.get("quality_window") or 20)

INTERNET_TEST_GLOBAL_TARGETS = CONFIG.get("internet_test_targets_global")
if not isinstance(INTERNET_TEST_GLOBAL_TARGETS, list) or not INTERNET_TEST_GLOBAL_TARGETS:
    INTERNET_TEST_GLOBAL_TARGETS = CONFIG.get("internet_test_ips")
if not isinstance(INTERNET_TEST_GLOBAL_TARGETS, list) or not INTERNET_TEST_GLOBAL_TARGETS:
    INTERNET_TEST_GLOBAL_TARGETS = ["1.1.1.1", "8.8.8.8"]
INTERNET_TEST_GLOBAL_TARGETS = [str(x).strip() for x in INTERNET_TEST_GLOBAL_TARGETS if str(x).strip()]
if not INTERNET_TEST_GLOBAL_TARGETS:
    INTERNET_TEST_GLOBAL_TARGETS = ["1.1.1.1", "8.8.8.8"]

INTERNET_TEST_IR_TARGETS = CONFIG.get("internet_test_targets_ir")
if not isinstance(INTERNET_TEST_IR_TARGETS, list) or not INTERNET_TEST_IR_TARGETS:
    INTERNET_TEST_IR_TARGETS = []
INTERNET_TEST_IR_TARGETS = [str(x).strip() for x in INTERNET_TEST_IR_TARGETS if str(x).strip()]

NFT_TABLE_FAMILY = str(CONFIG.get("nft_table_family") or "inet")
NFT_TABLE_NAME = str(CONFIG.get("nft_table_name") or "wanmon")

WANS: dict[str, dict[str, Any]] = CONFIG.get("wans") or {}

STATE_PATH = os.environ.get("WAN_PANEL_STATE") or os.path.join(BASE_DIR, "wan-panel-state.json")
STATE_VERSION = 1
STATE_FLUSH_INTERVAL_SECONDS = 5.0

state_lock = threading.Lock()
state_file_lock = threading.Lock()

last_counter_values = {}

last_cpu_times = None

health_state = {
    wan_id: {
        "gateway_online": None,
        "internet_online": None,
        "internet_ir_online": None,
        "gateway_rtt_ms": None,
        "gateway_jitter_ms": None,
        "gateway_loss_percent": None,
        "internet_rtt_ms": None,
        "internet_jitter_ms": None,
        "internet_loss_percent": None,
        "internet_target": None,
        "internet_ir_rtt_ms": None,
        "internet_ir_jitter_ms": None,
        "internet_ir_loss_percent": None,
        "internet_ir_target": None,
        "last_checked": 0,
    }
    for wan_id in WANS.keys()
}

quality_samples = {
    wan_id: {
        "gateway_success": deque(maxlen=QUALITY_WINDOW),
        "gateway_rtt": deque(maxlen=QUALITY_WINDOW),
        "internet_success": deque(maxlen=QUALITY_WINDOW),
        "internet_rtt": deque(maxlen=QUALITY_WINDOW),
        "internet_ir_success": deque(maxlen=QUALITY_WINDOW),
        "internet_ir_rtt": deque(maxlen=QUALITY_WINDOW),
    }
    for wan_id in WANS.keys()
}

current_snapshot = {
    "timestamp": int(time.time()),
    "default_wan": None,
    "wans": [],
    "system": {},
    "error": None,
}

history = deque(maxlen=HISTORY_LIMIT)


IP_IFACE_CACHE_TTL_SECONDS = 30.0
_ip_iface_cache = {
    "timestamp": 0.0,
    "map": {},
}


def run_command(args: Sequence[str], timeout: float = 3.0):
    try:
        result = subprocess.run(
            list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 124


def read_nft_counters():
    stdout, stderr, code = run_command(
        ["nft", "-j", "list", "counters", "table", NFT_TABLE_FAMILY, NFT_TABLE_NAME],
        timeout=2,
    )

    if code != 0:
        return {}, stderr or "nft command failed"

    if not stdout:
        return {}, "nft returned empty output"

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as ex:
        return {}, f"Invalid nft JSON: {ex}"

    counters = {}

    for item in data.get("nftables", []):
        counter = item.get("counter")
        if not counter:
            continue

        name = counter.get("name")
        bytes_count = counter.get("bytes", 0)

        if name:
            counters[name] = int(bytes_count)

    return counters, None


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def load_persistent_state(path: str, wans: dict[str, dict[str, Any]]) -> dict[str, Any]:
    base: dict[str, Any] = {
        "version": STATE_VERSION,
        "updated_at": 0,
        "wans": {},
    }

    data: dict[str, Any] | None = None
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
                if isinstance(raw, dict):
                    data = raw
        except (OSError, json.JSONDecodeError):
            data = None

    data_wans = {}
    if isinstance(data, dict):
        data_wans = data.get("wans") if isinstance(data.get("wans"), dict) else {}
        base["updated_at"] = _safe_int(data.get("updated_at")) or 0

    for wan_id in wans.keys():
        entry = data_wans.get(wan_id, {}) if isinstance(data_wans, dict) else {}
        if not isinstance(entry, dict):
            entry = {}

        base["wans"][wan_id] = {
            "download_total_bytes": _safe_int(entry.get("download_total_bytes")),
            "upload_total_bytes": _safe_int(entry.get("upload_total_bytes")),
            "last_nft_download_bytes": _safe_int(entry.get("last_nft_download_bytes")),
            "last_nft_upload_bytes": _safe_int(entry.get("last_nft_upload_bytes")),
            "last_seen_at": _safe_int(entry.get("last_seen_at")),
            "seeded_at": _safe_int(entry.get("seeded_at")),
        }

    return base


def _update_total_for_direction(
    entry: dict[str, Any],
    current_raw: int | None,
    now: int,
    last_key: str,
    total_key: str,
):
    if current_raw is None:
        if entry.get(total_key) is None:
            entry[total_key] = 0
        return

    current_raw = int(current_raw)
    last = _safe_int(entry.get(last_key))
    total = _safe_int(entry.get(total_key)) or 0

    if last is None:
        if total == 0:
            total = current_raw
            if not entry.get("seeded_at"):
                entry["seeded_at"] = now
    else:
        delta = current_raw - last
        if delta < 0:
            delta = current_raw
        if delta > 0:
            total += delta

    entry[last_key] = current_raw
    entry[total_key] = total


def update_persistent_totals(
    wan_id: str,
    upload_raw: int | None,
    download_raw: int | None,
    now: int,
):
    global state_dirty

    with state_file_lock:
        entry = persistent_state["wans"].get(wan_id)
        if not isinstance(entry, dict):
            entry = {
                "download_total_bytes": None,
                "upload_total_bytes": None,
                "last_nft_download_bytes": None,
                "last_nft_upload_bytes": None,
                "last_seen_at": None,
                "seeded_at": None,
            }
            persistent_state["wans"][wan_id] = entry

        _update_total_for_direction(entry, upload_raw, now, "last_nft_upload_bytes", "upload_total_bytes")
        _update_total_for_direction(entry, download_raw, now, "last_nft_download_bytes", "download_total_bytes")

        if upload_raw is not None or download_raw is not None:
            entry["last_seen_at"] = now
        elif entry.get("last_seen_at") is None:
            entry["last_seen_at"] = now

        persistent_state["updated_at"] = now
        state_dirty = True

        return dict(entry)


def get_persistent_wan_state(wan_id: str) -> dict[str, Any]:
    with state_file_lock:
        entry = persistent_state["wans"].get(wan_id)
        if not isinstance(entry, dict):
            return {
                "download_total_bytes": 0,
                "upload_total_bytes": 0,
            }
        return dict(entry)


def flush_persistent_state_if_needed(now: float):
    global last_state_flush
    global state_dirty

    if (now - last_state_flush) < STATE_FLUSH_INTERVAL_SECONDS:
        return

    with state_file_lock:
        if not state_dirty:
            return
        if (now - last_state_flush) < STATE_FLUSH_INTERVAL_SECONDS:
            return

        data = {
            "version": STATE_VERSION,
            "updated_at": int(now),
            "wans": persistent_state["wans"],
        }

        tmp_path = f"{STATE_PATH}.tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=True, indent=2, sort_keys=True)
            os.replace(tmp_path, STATE_PATH)
            last_state_flush = now
            state_dirty = False
        except OSError:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass


persistent_state = load_persistent_state(STATE_PATH, WANS)
state_dirty = False
last_state_flush = 0.0


PING_RTT_RE = re.compile(r"time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms")
PING_RESOLVED_IP_RE = re.compile(r"^PING\s+[^\s]+\s+\(([^)]+)\)")

NEIGH_OK_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}
NEIGH_BAD_STATES = {"FAILED", "INCOMPLETE"}


def ping_once(ip: str, timeout: int = 1, source_ip: str | None = None) -> tuple[bool, float | None]:
    args = ["ping", "-n", "-c", "1", "-W", str(timeout)]
    if source_ip:
        args.extend(["-I", source_ip])
    args.append(ip)

    stdout, stderr, code = run_command(args, timeout=timeout + 1)

    if code != 0:
        return False, None

    match = PING_RTT_RE.search(stdout)
    if not match:
        return True, None

    try:
        return True, float(match.group(1))
    except ValueError:
        return True, None


def ping_probe_once(target: str, timeout: int = 1, source_ip: str | None = None) -> tuple[bool, float | None, str | None]:
    args = ["ping", "-n", "-c", "1", "-W", str(timeout)]
    if source_ip:
        args.extend(["-I", source_ip])
    args.append(target)

    stdout, _, code = run_command(args, timeout=timeout + 1)

    resolved_ip = None
    if stdout:
        first_line = stdout.splitlines()[0] if stdout.splitlines() else ""
        match = PING_RESOLVED_IP_RE.search(first_line)
        if match:
            resolved_ip = match.group(1)

    if code != 0:
        return False, None, resolved_ip

    match = PING_RTT_RE.search(stdout)
    if not match:
        return True, None, resolved_ip

    try:
        return True, float(match.group(1)), resolved_ip
    except ValueError:
        return True, None, resolved_ip


def tcp_connect_once(
    ip: str,
    port: int = 443,
    timeout: float = 1.0,
    source_ip: str | None = None,
) -> tuple[bool, float | None]:
    if not ip:
        return False, None

    started = time.time()
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if source_ip:
            sock.bind((source_ip, 0))

        sock.connect((ip, int(port)))
        rtt_ms = (time.time() - started) * 1000.0
        return True, round(rtt_ms, 1)
    except ConnectionRefusedError:
        rtt_ms = (time.time() - started) * 1000.0
        return True, round(rtt_ms, 1)
    except OSError:
        return False, None
    finally:
        try:
            if sock:
                sock.close()
        except OSError:
            pass


def probe_internet_target(
    target: str,
    timeout: int = 1,
    source_ip: str | None = None,
    tcp_fallback_port: int = 443,
) -> tuple[bool, float | None]:
    ok, rtt, resolved_ip = ping_probe_once(target, timeout=timeout, source_ip=source_ip)
    if ok:
        return True, rtt

    if resolved_ip:
        tcp_ok, tcp_rtt = tcp_connect_once(
            resolved_ip,
            port=tcp_fallback_port,
            timeout=float(timeout),
            source_ip=source_ip,
        )
        if tcp_ok:
            return True, tcp_rtt

    return False, None


def read_neighbor_state(ip: str, iface: str | None = None) -> str | None:
    if not ip:
        return None

    args = ["ip", "-j", "neigh", "show", "to", ip]
    if iface:
        args.extend(["dev", iface])

    stdout, _, code = run_command(args, timeout=1.2)
    if code != 0 or not stdout:
        return None

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return None

    if not isinstance(data, list):
        return None

    for entry in data:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("dst") or "") != ip:
            continue
        state = entry.get("state")
        if isinstance(state, list):
            state = " ".join(str(s) for s in state)
        return str(state) if state else None

    return None


def is_neighbor_reachable(ip: str, iface: str | None = None) -> tuple[bool | None, str | None]:
    state = read_neighbor_state(ip, iface)
    if not state:
        return None, None

    tokens = [t for t in re.split(r"[,\s]+", state.upper()) if t]

    if any(t in NEIGH_BAD_STATES for t in tokens):
        return False, state

    if any(t in NEIGH_OK_STATES for t in tokens):
        return True, state

    return None, state


def compute_loss_percent(success_window: deque) -> float | None:
    if not success_window:
        return None
    total = len(success_window)
    lost = sum(1 for ok in success_window if not ok)
    return round((lost / total) * 100.0, 1)


def compute_rtt_stats(rtt_window: deque) -> tuple[float | None, float | None]:
    values = [x for x in rtt_window if isinstance(x, (int, float))]
    if not values:
        return None, None

    avg = round(sum(values) / len(values), 1)
    jitter = round(statistics.pstdev(values), 1) if len(values) >= 2 else None
    return avg, jitter


def get_default_wan():
    stdout, _, code = run_command(["ip", "route", "show", "default"], timeout=1)

    if code != 0 or not stdout:
        return None

    first_line = stdout.splitlines()[0]

    for wan_id, wan in WANS.items():
        if f"via {wan['gateway']}" in first_line:
            return wan_id

    return None


def format_mbps(bytes_per_second):
    return round((bytes_per_second * 8) / 1_000_000, 2)


def _read_first_line(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.readline().strip()
    except OSError:
        return None


def _read_int(path: str) -> int | None:
    line = _read_first_line(path)
    if line is None:
        return None
    try:
        return int(line.strip())
    except ValueError:
        return None


def read_ip_iface_map() -> dict[str, str]:
    """Map local IPs to interface names using iproute2 JSON output."""
    stdout, stderr, code = run_command(["ip", "-j", "address", "show"], timeout=2)
    if code != 0 or not stdout:
        return {}

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {}

    if not isinstance(data, list):
        return {}

    mapping: dict[str, str] = {}

    for link in data:
        if not isinstance(link, dict):
            continue
        ifname = link.get("ifname")
        if not ifname:
            continue

        addr_info = link.get("addr_info")
        if not isinstance(addr_info, list):
            continue

        for addr in addr_info:
            if not isinstance(addr, dict):
                continue
            local = addr.get("local")
            if local:
                mapping[str(local)] = str(ifname)

    return mapping


def get_ip_iface_map_cached(now: float) -> dict[str, str]:
    global _ip_iface_cache
    last_ts = float(_ip_iface_cache.get("timestamp") or 0.0)
    if (now - last_ts) < IP_IFACE_CACHE_TTL_SECONDS and isinstance(_ip_iface_cache.get("map"), dict):
        return _ip_iface_cache["map"]

    mapping = read_ip_iface_map()
    _ip_iface_cache = {
        "timestamp": now,
        "map": mapping,
    }
    return mapping


def read_interface_metrics(iface: str) -> dict[str, Any] | None:
    if not iface:
        return None

    base = os.path.join("/sys/class/net", iface)
    operstate = _read_first_line(os.path.join(base, "operstate"))
    mtu = _read_int(os.path.join(base, "mtu"))

    rx_dropped = _read_int(os.path.join(base, "statistics", "rx_dropped"))
    tx_dropped = _read_int(os.path.join(base, "statistics", "tx_dropped"))
    rx_errors = _read_int(os.path.join(base, "statistics", "rx_errors"))
    tx_errors = _read_int(os.path.join(base, "statistics", "tx_errors"))

    iface_up: bool | None
    if operstate == "up":
        iface_up = True
    elif operstate == "down":
        iface_up = False
    else:
        iface_up = None

    return {
        "iface": iface,
        "operstate": operstate,
        "up": iface_up,
        "mtu": mtu,
        "rx_dropped": rx_dropped,
        "tx_dropped": tx_dropped,
        "rx_errors": rx_errors,
        "tx_errors": tx_errors,
    }


def read_uptime_seconds() -> float | None:
    line = _read_first_line("/proc/uptime")
    if not line:
        return None
    try:
        return float(line.split()[0])
    except (ValueError, IndexError):
        return None


def read_meminfo_bytes() -> dict:
    result: dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for raw in f:
                if ":" not in raw:
                    continue
                key, value = raw.split(":", 1)
                parts = value.strip().split()
                if not parts:
                    continue
                try:
                    number = int(parts[0])
                except ValueError:
                    continue
                unit = parts[1].lower() if len(parts) > 1 else "kb"
                if unit == "kb":
                    result[key] = number * 1024
                else:
                    result[key] = number
    except OSError:
        return {}
    return result


def read_cpu_times() -> dict | None:
    line = _read_first_line("/proc/stat")
    if not line or not line.startswith("cpu "):
        return None
    parts = line.split()
    # cpu user nice system idle iowait irq softirq steal guest guest_nice
    if len(parts) < 5:
        return None
    try:
        values = [int(x) for x in parts[1:]]
    except ValueError:
        return None

    idle = values[3] + (values[4] if len(values) > 4 else 0)
    total = sum(values)
    return {"idle": idle, "total": total}


def get_system_metrics() -> dict:
    global last_cpu_times

    cpu_times = read_cpu_times()
    cpu_percent = None

    if cpu_times and last_cpu_times:
        total_delta = cpu_times["total"] - last_cpu_times["total"]
        idle_delta = cpu_times["idle"] - last_cpu_times["idle"]
        if total_delta > 0:
            cpu_percent = round(max(0.0, min(100.0, 100.0 * (1.0 - (idle_delta / total_delta)))), 1)

    if cpu_times:
        last_cpu_times = cpu_times

    mem = read_meminfo_bytes()

    mem_total = mem.get("MemTotal")
    mem_available = mem.get("MemAvailable")
    mem_used = None
    mem_percent = None

    if mem_total and mem_available is not None:
        mem_used = max(mem_total - mem_available, 0)
        mem_percent = round((mem_used / mem_total) * 100.0, 1) if mem_total else None

    swap_total = mem.get("SwapTotal")
    swap_free = mem.get("SwapFree")
    swap_used = None
    swap_percent = None

    if swap_total is not None and swap_free is not None:
        swap_used = max(swap_total - swap_free, 0)
        swap_percent = round((swap_used / swap_total) * 100.0, 1) if swap_total else 0.0

    try:
        load1, load5, load15 = os.getloadavg()
        load = {"1": round(load1, 2), "5": round(load5, 2), "15": round(load15, 2)}
    except OSError:
        load = None

    disk = None
    try:
        usage = shutil.disk_usage("/")
        disk = {
            "path": "/",
            "total": int(usage.total),
            "used": int(usage.used),
            "free": int(usage.free),
            "percent": round((usage.used / usage.total) * 100.0, 1) if usage.total else None,
        }
    except OSError:
        disk = None

    uptime_seconds = read_uptime_seconds()

    return {
        "cpu_percent": cpu_percent,
        "memory": {
            "total": mem_total,
            "used": mem_used,
            "available": mem_available,
            "percent": mem_percent,
        },
        "swap": {
            "total": swap_total,
            "used": swap_used,
            "free": swap_free,
            "percent": swap_percent,
        },
        "disk": disk,
        "load": load,
        "uptime_seconds": uptime_seconds,
    }


def read_routes():
    route_out, route_err, route_code = run_command(["ip", "route"], timeout=2)
    rule_out, rule_err, rule_code = run_command(["ip", "rule"], timeout=2)

    outputs: list[str] = []

    if route_code == 0:
        outputs.append(route_out)
    else:
        outputs.append(route_err or route_out or "Failed to read ip route")

    outputs.append("\n--- ip rule ---\n")

    if rule_code == 0:
        outputs.append(rule_out)
    else:
        outputs.append(rule_err or rule_out or "Failed to read ip rule")

    return "\n".join(outputs).strip()


def speed_collector_loop():
    global current_snapshot

    while True:
        started_at = time.time()

        counters, error = read_nft_counters()
        default_wan = get_default_wan()
        counters_ok = error is None

        combined_error = None
        if startup_error and error:
            combined_error = f"{startup_error}; {error}"
        else:
            combined_error = startup_error or error

        items = []
        ip_iface_map = get_ip_iface_map_cached(started_at)
        iface_metrics_cache: dict[str, dict[str, Any] | None] = {}

        for wan_id, wan in sorted(WANS.items(), key=lambda kv: (kv[1].get("metric", 0), kv[0])):
            upload_raw = counters.get(wan["upload_counter"], 0)
            download_raw = counters.get(wan["download_counter"], 0)

            upload_present = wan["upload_counter"] in counters
            download_present = wan["download_counter"] in counters

            if counters_ok:
                state_entry = update_persistent_totals(
                    wan_id,
                    upload_raw if upload_present else None,
                    download_raw if download_present else None,
                    int(started_at),
                )
            else:
                state_entry = get_persistent_wan_state(wan_id)

            upload_total = int(state_entry.get("upload_total_bytes") or 0)
            download_total = int(state_entry.get("download_total_bytes") or 0)

            upload_bps = 0.0
            download_bps = 0.0

            if wan_id in last_counter_values:
                last = last_counter_values[wan_id]
                elapsed = max(started_at - last["timestamp"], 0.2)

                upload_bps = max(upload_raw - last["upload_total"], 0) / elapsed
                download_bps = max(download_raw - last["download_total"], 0) / elapsed

            last_counter_values[wan_id] = {
                "timestamp": started_at,
                "upload_total": upload_raw,
                "download_total": download_raw,
            }

            with state_lock:
                health = health_state.get(wan_id, {})

            iface = ip_iface_map.get(wan.get("source_ip") or "")
            if iface and iface not in iface_metrics_cache:
                iface_metrics_cache[iface] = read_interface_metrics(iface)

            iface_metrics = iface_metrics_cache.get(iface) if iface else None

            items.append({
                "id": wan_id,
                "name": wan["name"],
                "source_ip": wan["source_ip"],
                "gateway": wan["gateway"],
                "metric": wan["metric"],
                "iface": iface_metrics.get("iface") if iface_metrics else None,
                "iface_state": iface_metrics.get("operstate") if iface_metrics else None,
                "iface_up": iface_metrics.get("up") if iface_metrics else None,
                "iface_mtu": iface_metrics.get("mtu") if iface_metrics else None,
                "iface_rx_dropped": iface_metrics.get("rx_dropped") if iface_metrics else None,
                "iface_tx_dropped": iface_metrics.get("tx_dropped") if iface_metrics else None,
                "iface_rx_errors": iface_metrics.get("rx_errors") if iface_metrics else None,
                "iface_tx_errors": iface_metrics.get("tx_errors") if iface_metrics else None,
                "gateway_online": health.get("gateway_online"),
                "internet_online": health.get("internet_online"),
                "internet_ir_online": health.get("internet_ir_online"),
                "gateway_rtt_ms": health.get("gateway_rtt_ms"),
                "gateway_jitter_ms": health.get("gateway_jitter_ms"),
                "gateway_loss_percent": health.get("gateway_loss_percent"),
                "internet_rtt_ms": health.get("internet_rtt_ms"),
                "internet_jitter_ms": health.get("internet_jitter_ms"),
                "internet_loss_percent": health.get("internet_loss_percent"),
                "internet_target": health.get("internet_target"),
                "internet_ir_rtt_ms": health.get("internet_ir_rtt_ms"),
                "internet_ir_jitter_ms": health.get("internet_ir_jitter_ms"),
                "internet_ir_loss_percent": health.get("internet_ir_loss_percent"),
                "internet_ir_target": health.get("internet_ir_target"),
                "health_last_checked": health.get("last_checked", 0),
                "upload_total": upload_total,
                "download_total": download_total,
                "upload_mbps": format_mbps(upload_bps),
                "download_mbps": format_mbps(download_bps),
            })

        snapshot = {
            "timestamp": int(started_at),
            "default_wan": default_wan,
            "wans": items,
            "system": get_system_metrics(),
            "error": combined_error,
        }

        with state_lock:
            current_snapshot = snapshot

            history.append({
                "timestamp": snapshot["timestamp"],
                "wans": [
                    {
                        "id": item["id"],
                        "upload_mbps": item["upload_mbps"],
                        "download_mbps": item["download_mbps"],
                    }
                    for item in items
                ]
            })

        elapsed = time.time() - started_at
        sleep_for = max(SPEED_INTERVAL_SECONDS - elapsed, 0.05)
        flush_persistent_state_if_needed(time.time())
        time.sleep(sleep_for)


def health_collector_loop():
    while True:
        loop_started = time.time()
        ip_iface_map = get_ip_iface_map_cached(loop_started)
        for wan_id, wan in WANS.items():
            now = int(time.time())

            samples = quality_samples.get(wan_id)
            if not samples:
                samples = {
                    "gateway_success": deque(maxlen=QUALITY_WINDOW),
                    "gateway_rtt": deque(maxlen=QUALITY_WINDOW),
                    "internet_success": deque(maxlen=QUALITY_WINDOW),
                    "internet_rtt": deque(maxlen=QUALITY_WINDOW),
                    "internet_ir_success": deque(maxlen=QUALITY_WINDOW),
                    "internet_ir_rtt": deque(maxlen=QUALITY_WINDOW),
                }
                quality_samples[wan_id] = samples

            iface = ip_iface_map.get(wan.get("source_ip") or "")

            gateway_online, gateway_rtt_ms = ping_once(
                wan.get("gateway", ""),
                timeout=1,
                source_ip=wan.get("source_ip") or None,
            )

            if not gateway_online:
                neigh_ok, _ = is_neighbor_reachable(wan.get("gateway", ""), iface)
                if neigh_ok is True:
                    gateway_online = True
                    gateway_rtt_ms = None

            samples["gateway_success"].append(gateway_online)
            samples["gateway_rtt"].append(gateway_rtt_ms)

            internet_online = False
            internet_rtt_ms = None
            internet_target = None

            # Test internet independently from gateway reachability.
            for target in INTERNET_TEST_GLOBAL_TARGETS:
                ok, rtt = probe_internet_target(
                    target,
                    timeout=1,
                    source_ip=wan.get("source_ip") or None,
                )
                if ok:
                    internet_online = True
                    internet_rtt_ms = rtt
                    internet_target = target
                    break

            samples["internet_success"].append(internet_online)
            samples["internet_rtt"].append(internet_rtt_ms)

            internet_ir_online: bool | None = None
            internet_ir_rtt_ms = None
            internet_ir_target = None

            if INTERNET_TEST_IR_TARGETS:
                internet_ir_online = False
                for target in INTERNET_TEST_IR_TARGETS:
                    ok, rtt = probe_internet_target(
                        target,
                        timeout=1,
                        source_ip=wan.get("source_ip") or None,
                    )
                    if ok:
                        internet_ir_online = True
                        internet_ir_rtt_ms = rtt
                        internet_ir_target = target
                        break

                samples["internet_ir_success"].append(internet_ir_online)
                samples["internet_ir_rtt"].append(internet_ir_rtt_ms)
            else:
                if samples.get("internet_ir_success"):
                    samples["internet_ir_success"].clear()
                if samples.get("internet_ir_rtt"):
                    samples["internet_ir_rtt"].clear()

            gateway_loss_percent = compute_loss_percent(samples["gateway_success"])
            internet_loss_percent = compute_loss_percent(samples["internet_success"])
            internet_ir_loss_percent = compute_loss_percent(samples["internet_ir_success"])

            gateway_avg_rtt_ms, gateway_jitter_ms = compute_rtt_stats(samples["gateway_rtt"])
            internet_avg_rtt_ms, internet_jitter_ms = compute_rtt_stats(samples["internet_rtt"])
            internet_ir_avg_rtt_ms, internet_ir_jitter_ms = compute_rtt_stats(samples["internet_ir_rtt"])

            with state_lock:
                health_state[wan_id] = {
                    "gateway_online": gateway_online,
                    "internet_online": internet_online,
                    "internet_ir_online": internet_ir_online,
                    "gateway_rtt_ms": gateway_avg_rtt_ms,
                    "gateway_jitter_ms": gateway_jitter_ms,
                    "gateway_loss_percent": gateway_loss_percent,
                    "internet_rtt_ms": internet_avg_rtt_ms,
                    "internet_jitter_ms": internet_jitter_ms,
                    "internet_loss_percent": internet_loss_percent,
                    "internet_target": internet_target,
                    "internet_ir_rtt_ms": internet_ir_avg_rtt_ms,
                    "internet_ir_jitter_ms": internet_ir_jitter_ms,
                    "internet_ir_loss_percent": internet_ir_loss_percent,
                    "internet_ir_target": internet_ir_target,
                    "last_checked": now,
                }

            # small gap so health checks do not spike the server
            time.sleep(0.1)

        time.sleep(HEALTH_INTERVAL_SECONDS)


@app.route("/")
def index():
    return render_template_string(PAGE_HTML)


@app.route("/api/status")
def api_status():
    with state_lock:
        return jsonify(current_snapshot)


@app.route("/api/history")
def api_history():
    with state_lock:
        return jsonify(list(history))


@app.route("/api/routes")
def api_routes():
    return jsonify({
        "output": read_routes()
    })


PAGE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>WAN Live Panel</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style>
        :root {
            --bg: #0f172a;
            --card: #111827;
            --card2: #020617;
            --border: #1f2937;
            --text: #e5e7eb;
            --muted: #94a3b8;
            --green: #22c55e;
            --red: #ef4444;
            --blue: #38bdf8;
            --yellow: #f59e0b;
            --purple: #a855f7;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font-family: Arial, sans-serif;
        }

        .container {
            padding: 18px;
        }

        .header {
            display: flex;
            justify-content: space-between;
            gap: 16px;
            flex-wrap: wrap;
            margin-bottom: 16px;
        }

        h1 {
            margin: 0 0 8px;
            font-size: 26px;
        }

        .subtitle {
            color: var(--muted);
            font-size: 14px;
            line-height: 1.6;
        }

        .actions {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: flex-start;
        }

        .tabs {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }

        .section-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            margin-bottom: 10px;
        }

        button {
            border: 0;
            border-radius: 10px;
            padding: 10px 12px;
            cursor: pointer;
            background: #2563eb;
            color: #fff;
            font-weight: bold;
        }

        button.tab {
            background: #374151;
            color: #e5e7eb;
        }

        button.tab.active {
            background: #075985;
            color: #bae6fd;
        }

        button.gray {
            background: #374151;
        }

        button.red {
            background: #b91c1c;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(270px, 1fr));
            gap: 14px;
        }

        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 16px;
            box-shadow: 0 12px 26px rgba(0,0,0,.22);
        }

        .wan-title {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .badges {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-bottom: 12px;
        }

        .badge {
            display: inline-block;
            padding: 4px 9px;
            border-radius: 100px;
            font-size: 11px;
            font-weight: bold;
        }

        .ok {
            background: #064e3b;
            color: #a7f3d0;
        }

        .bad {
            background: #7f1d1d;
            color: #fecaca;
        }

        .unknown {
            background: #374151;
            color: #d1d5db;
        }

        .active {
            background: #075985;
            color: #bae6fd;
        }

        .standby {
            background: #374151;
            color: #d1d5db;
        }

        .row {
            display: flex;
            justify-content: space-between;
            gap: 12px;
            margin: 8px 0;
            color: #cbd5e1;
            font-size: 14px;
        }

        .value {
            color: #fff;
            font-weight: bold;
            text-align: right;
            word-break: break-all;
        }

        .speed-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin: 14px 0;
        }

        .speed-box {
            background: var(--card2);
            border: 1px solid #1e293b;
            border-radius: 12px;
            padding: 12px;
            transition: transform .15s ease, border-color .15s ease;
        }

        .speed-box.flash {
            transform: scale(1.015);
            border-color: #38bdf8;
        }

        .speed-label {
            color: var(--muted);
            font-size: 12px;
            margin-bottom: 6px;
        }

        .speed-value {
            font-size: 24px;
            font-weight: bold;
            font-variant-numeric: tabular-nums;
        }

        .down {
            color: var(--blue);
        }

        .up {
            color: var(--green);
        }

        .section {
            margin-top: 18px;
        }

        .chart-wrap {
            height: 260px;
            background: var(--card2);
            border-radius: 14px;
            border: 1px solid #1e293b;
            padding: 10px;
        }

        canvas {
            width: 100%;
            height: 240px;
        }

        pre {
            background: var(--card2);
            border: 1px solid #1e293b;
            border-radius: 12px;
            padding: 12px;
            white-space: pre-wrap;
            overflow-x: auto;
            color: #d1d5db;
            max-height: 420px;
        }

        .error {
            margin: 10px 0;
            padding: 12px;
            background: #7f1d1d;
            color: #fecaca;
            border-radius: 12px;
            display: none;
        }

        .message {
            color: var(--yellow);
            margin-top: 8px;
            direction: rtl;
            text-align: right;
            unicode-bidi: plaintext;
        }

        .hint {
            color: var(--muted);
            font-size: 13px;
            margin-top: 8px;
        }

        .mini {
            color: var(--muted);
            font-size: 12px;
        }

        .sys-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 14px;
        }

        .sys-metric {
            margin: 12px 0;
        }

        .sys-top {
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            gap: 10px;
            color: #cbd5e1;
            font-size: 14px;
        }

        .sys-bar {
            margin-top: 8px;
            height: 10px;
            border-radius: 999px;
            background: #0b1220;
            border: 1px solid #1e293b;
            overflow: hidden;
        }

        .sys-bar > div {
            height: 100%;
            width: 0%;
            background: var(--blue);
            transition: width .15s ease;
        }

        .hidden {
            display: none;
        }

        .help {
            cursor: help;
            text-decoration: underline dotted var(--muted);
            text-underline-offset: 3px;
        }

        .badge[data-help] {
            cursor: help;
        }

        .tooltip {
            position: fixed;
            z-index: 9999;
            display: none;
            max-width: 380px;
            padding: 10px 12px;
            border-radius: 12px;
            background: var(--card2);
            border: 1px solid var(--border);
            color: var(--text);
            font-size: 13px;
            line-height: 1.6;
            direction: rtl;
            text-align: right;
            unicode-bidi: plaintext;
            pointer-events: none;
        }

        .tooltip.show {
            display: block;
        }
    </style>
</head>

<body>
<div class="container">
    <div class="header">
        <div>
            <h1>WAN Live Panel</h1>
            <div class="subtitle" id="lastUpdate">Loading...</div>
            <div class="subtitle" id="defaultWan">Default WAN: -</div>
            <div class="message" id="message" dir="rtl"></div>
        </div>

        <div class="actions">
            <div class="tabs">
                <button class="tab active" id="tabBtnWan" onclick="setTab('wan')">WAN / Panel</button>
                <button class="tab" id="tabBtnSystem" onclick="setTab('system')">System Resources</button>
            </div>
        </div>
    </div>

    <div class="error" id="errorBox"></div>

    <div id="tabWan">
        <div class="grid" id="cards"></div>

        <div class="card section">
            <div class="wan-title">Live Download Mbps</div>
            <div class="chart-wrap">
                <canvas id="downloadCanvas"></canvas>
            </div>
            <div class="hint">Speed updates every 1 second. Health status updates every few seconds.</div>
        </div>

        <div class="card section">
            <div class="wan-title">Live Upload Mbps</div>
            <div class="chart-wrap">
                <canvas id="uploadCanvas"></canvas>
            </div>
            <div class="hint">No external JS/CDN is used.</div>
        </div>

        <div class="card section">
            <div class="section-head">
                <div class="wan-title">Routes / Rules</div>
                <button class="gray" onclick="loadRoutes()">Show Routes</button>
            </div>
            <pre id="routesBox">Click Show Routes</pre>
        </div>
    </div>

    <div id="tabSystem" class="hidden">
        <div class="sys-grid">
            <div class="card">
                <div class="wan-title">CPU / Load</div>

                <div class="sys-metric">
                    <div class="sys-top"><span>CPU Usage</span><span class="value" id="sysCpu">-</span></div>
                    <div class="sys-bar"><div id="sysCpuBar"></div></div>
                </div>

                <div class="sys-metric">
                    <div class="sys-top"><span>Load (1/5/15)</span><span class="value" id="sysLoad">-</span></div>
                    <div class="mini">Load is relative to CPU cores.</div>
                </div>

                <div class="sys-metric">
                    <div class="sys-top"><span>Uptime</span><span class="value" id="sysUptime">-</span></div>
                </div>
            </div>

            <div class="card">
                <div class="wan-title">Memory</div>

                <div class="sys-metric">
                    <div class="sys-top"><span>RAM</span><span class="value" id="sysMem">-</span></div>
                    <div class="sys-bar"><div id="sysMemBar"></div></div>
                </div>

                <div class="sys-metric">
                    <div class="sys-top"><span>Swap</span><span class="value" id="sysSwap">-</span></div>
                    <div class="sys-bar"><div id="sysSwapBar"></div></div>
                </div>
            </div>

            <div class="card">
                <div class="wan-title">Disk</div>

                <div class="sys-metric">
                    <div class="sys-top"><span>Disk (/)</span><span class="value" id="sysDisk">-</span></div>
                    <div class="sys-bar"><div id="sysDiskBar"></div></div>
                </div>
                <div class="mini">Updates with the 1s status refresh.</div>
            </div>
        </div>
    </div>
</div>

<div id="tooltip" class="tooltip" dir="rtl"></div>

<script>
    const history = [];
    const maxPoints = 90;
    let firstRender = true;
    let lastRenderedSpeeds = {};
    let currentTab = "wan";
    let wanOrder = [];
    let historyLoaded = false;
    let historyLoadInProgress = false;
    const hoveredCards = {};

    const HELP_FA = {
        link: "وضعیت لینک اینترفیس (بالا/پایین بودن لینک).",
        gateway: "دسترس‌پذیری گیت‌وی از مبدا همین لینک (ICMP یا وضعیت neighbor/ARP).",
        internet: "دسترسی به اینترنت جهانی از مبدا همین لینک (ICMP یا TCP/443؛ اولین مقصد پاسخ‌گو انتخاب می‌شود).",
        internetIr: "دسترسی به اینترنت/سرویس داخل ایران از مبدا همین لینک (ICMP یا TCP/443؛ مقاصد از config خوانده می‌شود).",
        default: "یعنی مسیر پیش‌فرض فعلی سیستم روی همین لینک است.",
        standby: "یعنی مسیر پیش‌فرض فعلی سیستم روی این لینک نیست.",
        sourceIp: "آی‌پی مبدا تست‌ها (پینگ از همین آی‌پی ارسال می‌شود).",
        metric: "عدد کمتر یعنی اولویت بالاتر برای مسیر.",
        iface: "اینترفیس متناظر با آی‌پی مبدا.",
        ifStats: "آمار افتادگی و خطا برای دریافت/ارسال اینترفیس (تجمعی از زمان روشن شدن سیستم).",
        totals: "حجم کل ترافیک تجمعی خوانده‌شده از شمارنده‌ها.",
        healthCheck: "زمان سپری‌شده از آخرین تست سلامت.",
        rttLoss: "میانگین تاخیر و درصد عدم‌پاسخ در پنجرهٔ آخر.",
        jitter: "نوسان تاخیر در پنجرهٔ آخر.",
        target: "مقصد تست اینترنتی که پاسخ داده.",
        jitterTarget: "نوسان تاخیر و مقصد تست اینترنتی پاسخ‌گو.",
    };

    const paletteVars = ["--blue", "--purple", "--green", "--yellow", "--red"];
    let cachedPalette = null;

    function getCssVar(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    function getPalette() {
        if (cachedPalette) return cachedPalette;
        cachedPalette = paletteVars.map(v => getCssVar(v) || "#fff");
        return cachedPalette;
    }

    function hashString(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash);
    }

    function colorForWan(wanId) {
        const palette = getPalette();
        if (!wanId) return "#fff";
        return palette[hashString(wanId) % palette.length] || "#fff";
    }

    function setTab(tab) {
        currentTab = tab;

        const tabWan = document.getElementById("tabWan");
        const tabSystem = document.getElementById("tabSystem");

        const btnWan = document.getElementById("tabBtnWan");
        const btnSystem = document.getElementById("tabBtnSystem");

        if (tab === "system") {
            tabWan.classList.add("hidden");
            tabSystem.classList.remove("hidden");
            btnWan.classList.remove("active");
            btnSystem.classList.add("active");
        } else {
            tabSystem.classList.add("hidden");
            tabWan.classList.remove("hidden");
            btnSystem.classList.remove("active");
            btnWan.classList.add("active");

            // charts need a fresh draw after becoming visible
            drawChart("downloadCanvas", "download_mbps");
            drawChart("uploadCanvas", "upload_mbps");
        }
    }

    function formatBytes(bytes) {
        if (!bytes) return "0 B";
        if (bytes < 1024) return bytes + " B";

        const kb = bytes / 1024;
        if (kb < 1024) return kb.toFixed(2) + " KB";

        const mb = kb / 1024;
        if (mb < 1024) return mb.toFixed(2) + " MB";

        const gb = mb / 1024;
        if (gb < 1024) return gb.toFixed(2) + " GB";

        return (gb / 1024).toFixed(2) + " TB";
    }

    function formatMs(value) {
        if (value === null || value === undefined) return "-";
        const n = Number(value);
        if (Number.isNaN(n)) return "-";
        return n.toFixed(1) + " ms";
    }

    function formatPct(value) {
        if (value === null || value === undefined) return "-";
        const n = Number(value);
        if (Number.isNaN(n)) return "-";
        return n.toFixed(1) + "%";
    }

    function statusBadge(value, label) {
        let helpKey = "";
        if (label === "Link") helpKey = "link";
        else if (label === "Gateway") helpKey = "gateway";
        else if (label === "Internet") helpKey = "internet";
        else if (label === "IR") helpKey = "internetIr";

        const helpAttr = helpKey ? ` data-help="${helpKey}"` : "";

        if (value === true) {
            return `<span class="badge ok"${helpAttr}>${label} OK</span>`;
        }

        if (value === false) {
            return `<span class="badge bad"${helpAttr}>${label} DOWN</span>`;
        }

        return `<span class="badge unknown"${helpAttr}>${label} CHECKING</span>`;
    }

    function showMessage(text) {
        const box = document.getElementById("message");
        box.innerText = text;
        setTimeout(() => box.innerText = "", 7000);
    }

    // Custom tooltip (RTL) to avoid native title direction issues
    const tooltipEl = document.getElementById("tooltip");
    let activeTipEl = null;

    function getHelpTextFromEl(el) {
        if (!el) return null;
        const key = el.getAttribute("data-help");
        if (key && HELP_FA[key]) return HELP_FA[key];
        return null;
    }

    function positionTooltip(clientX, clientY) {
        if (!tooltipEl) return;
        const pad = 12;
        const offset = 14;

        let x = clientX + offset;
        let y = clientY + offset;

        tooltipEl.style.left = x + "px";
        tooltipEl.style.top = y + "px";

        const rect = tooltipEl.getBoundingClientRect();

        if (rect.right > window.innerWidth - pad) {
            x = Math.max(pad, window.innerWidth - pad - rect.width);
        }

        if (rect.bottom > window.innerHeight - pad) {
            y = Math.max(pad, window.innerHeight - pad - rect.height);
        }

        tooltipEl.style.left = x + "px";
        tooltipEl.style.top = y + "px";
    }

    function showTooltip(text, clientX, clientY) {
        if (!tooltipEl || !text) return;
        tooltipEl.innerText = text;
        tooltipEl.classList.add("show");
        positionTooltip(clientX, clientY);
    }

    function hideTooltip() {
        if (!tooltipEl) return;
        tooltipEl.classList.remove("show");
        activeTipEl = null;
    }

    function findHelpTarget(target) {
        if (!target || !target.closest) return null;
        return target.closest(".help, .badge");
    }

    document.addEventListener("mouseover", (ev) => {
        const el = findHelpTarget(ev.target);
        if (!el) return;

        const tip = getHelpTextFromEl(el);
        if (!tip) return;

        activeTipEl = el;
        showTooltip(tip, ev.clientX, ev.clientY);
    });

    document.addEventListener("mousemove", (ev) => {
        if (!tooltipEl || !tooltipEl.classList.contains("show")) return;
        positionTooltip(ev.clientX, ev.clientY);
    });

    document.addEventListener("mouseout", (ev) => {
        const el = findHelpTarget(ev.target);
        if (!el || el !== activeTipEl) return;

        const toEl = ev.relatedTarget && ev.relatedTarget.closest
            ? ev.relatedTarget.closest(".help, .badge")
            : null;

        if (toEl && toEl === activeTipEl) return;
        hideTooltip();
    });

    window.addEventListener("scroll", hideTooltip, { passive: true });

    // Click/tap fallback for devices without hover
    document.addEventListener("click", (ev) => {
        const el = ev.target && ev.target.closest
            ? ev.target.closest(".help, .badge")
            : null;

        if (!el) return;
        const key = el.getAttribute("data-help");
        const tip = (key && HELP_FA[key]) ? HELP_FA[key] : null;
        if (tip) {
            showMessage(tip);
        }
    });

    async function loadHistoryOnce() {
        if (historyLoaded || historyLoadInProgress) return;
        historyLoadInProgress = true;

        try {
            const response = await fetch("/api/history?t=" + Date.now(), { cache: "no-store" });
            const data = await response.json();

            if (Array.isArray(data)) {
                history.length = 0;
                data.slice(-maxPoints).forEach(p => history.push(p));
            }

            historyLoaded = true;

            if (currentTab === "wan") {
                drawChart("downloadCanvas", "download_mbps");
                drawChart("uploadCanvas", "upload_mbps");
            }
        } catch (e) {
            // keep panel responsive even if history fetch fails
        } finally {
            historyLoadInProgress = false;
        }
    }

    async function loadStatus() {
        try {
            const response = await fetch("/api/status?t=" + Date.now(), { cache: "no-store" });
            const data = await response.json();

            renderStatus(data);
        } catch (e) {
            document.getElementById("errorBox").style.display = "block";
            document.getElementById("errorBox").innerText = "Panel fetch error: " + e;
        }
    }

    function renderStatus(data) {
        const errorBox = document.getElementById("errorBox");

        if (data.error) {
            errorBox.style.display = "block";
            errorBox.innerText = data.error;
        } else {
            errorBox.style.display = "none";
        }

        document.getElementById("lastUpdate").innerText =
            "Last update: " + new Date(data.timestamp * 1000).toLocaleString();

        const wansSorted = (data.wans || []).slice().sort((a, b) => {
            const am = Number(a.metric ?? 0);
            const bm = Number(b.metric ?? 0);
            if (am !== bm) return am - bm;
            return String(a.id || "").localeCompare(String(b.id || ""));
        });
        data.wans = wansSorted;

        const defId = data.default_wan || null;
        let defText = defId || "unknown";
        if (defId) {
            const defWan = wansSorted.find(w => w.id === defId);
            if (defWan && defWan.name) {
                defText = defId + " - " + defWan.name;
            }
        }

        document.getElementById("defaultWan").innerText =
            "Default WAN: " + defText;

        wanOrder = wansSorted.map(w => w.id);

        renderCards(data);
        renderSystem(data.system);
        pushHistory(data);

        if (!historyLoaded) {
            loadHistoryOnce();
        }

        if (currentTab === "wan") {
            drawChart("downloadCanvas", "download_mbps");
            drawChart("uploadCanvas", "upload_mbps");
        }

        firstRender = false;
    }

    function formatSeconds(seconds) {
        if (seconds === null || seconds === undefined) return "-";
        const s = Math.max(0, Math.floor(seconds));
        const d = Math.floor(s / 86400);
        const h = Math.floor((s % 86400) / 3600);
        const m = Math.floor((s % 3600) / 60);
        if (d > 0) return `${d}d ${h}h ${m}m`;
        if (h > 0) return `${h}h ${m}m`;
        return `${m}m`;
    }

    function clampPercent(value) {
        if (value === null || value === undefined) return 0;
        return Math.max(0, Math.min(100, value));
    }

    function pickBarColor(percent) {
        if (percent >= 90) return "var(--red)";
        if (percent >= 75) return "var(--yellow)";
        if (percent >= 50) return "var(--blue)";
        return "var(--green)";
    }

    function renderSystem(sys) {
        if (!sys) return;

        const cpuPercent = (sys.cpu_percent === null || sys.cpu_percent === undefined)
            ? null
            : Number(sys.cpu_percent);

        const cpu = (cpuPercent === null || Number.isNaN(cpuPercent))
            ? "-"
            : cpuPercent.toFixed(1) + "%";

        const mem = sys.memory || {};
        const memText = (mem.total && mem.used !== null && mem.used !== undefined)
            ? `${formatBytes(mem.used)} / ${formatBytes(mem.total)} (${(mem.percent ?? 0).toFixed(1)}%)`
            : "-";

        const swap = sys.swap || {};
        const swapText = (swap.total && swap.used !== null && swap.used !== undefined)
            ? `${formatBytes(swap.used)} / ${formatBytes(swap.total)} (${(swap.percent ?? 0).toFixed(1)}%)`
            : (swap.total === 0 ? "0 / 0 (0.0%)" : "-");

        const disk = sys.disk || null;
        const diskText = (disk && disk.total)
            ? `${formatBytes(disk.used)} / ${formatBytes(disk.total)} (${(disk.percent ?? 0).toFixed(1)}%)`
            : "-";

        const load = sys.load;
        const loadText = load
            ? `${load["1"]} / ${load["5"]} / ${load["15"]}`
            : "-";

        document.getElementById("sysCpu").innerText = cpu;
        document.getElementById("sysMem").innerText = memText;
        document.getElementById("sysSwap").innerText = swapText;
        document.getElementById("sysDisk").innerText = diskText;
        document.getElementById("sysLoad").innerText = loadText;
        document.getElementById("sysUptime").innerText = formatSeconds(sys.uptime_seconds);

        const cpuBar = document.getElementById("sysCpuBar");
        const memBar = document.getElementById("sysMemBar");
        const swapBar = document.getElementById("sysSwapBar");
        const diskBar = document.getElementById("sysDiskBar");

        const cpuBarValue = clampPercent(cpuPercent);
        cpuBar.style.width = cpuBarValue + "%";
        cpuBar.style.background = pickBarColor(cpuBarValue);

        const memBarValue = clampPercent(mem.percent);
        memBar.style.width = memBarValue + "%";
        memBar.style.background = pickBarColor(memBarValue);

        const swapBarValue = clampPercent(swap.percent);
        swapBar.style.width = swapBarValue + "%";
        swapBar.style.background = pickBarColor(swapBarValue);

        const diskBarValue = clampPercent(disk ? disk.percent : null);
        diskBar.style.width = diskBarValue + "%";
        diskBar.style.background = pickBarColor(diskBarValue);
    }

    function renderCards(data) {
        const cards = document.getElementById("cards");

        if (firstRender) {
            cards.innerHTML = "";

            data.wans.forEach(wan => {
                const div = document.createElement("div");
                div.className = "card";
                div.id = "card-" + wan.id;

                div.addEventListener("mouseenter", () => {
                    hoveredCards[wan.id] = true;
                });

                div.addEventListener("mouseleave", () => {
                    hoveredCards[wan.id] = false;
                });

                cards.appendChild(div);
            });
        }

        data.wans.forEach(wan => {
            const isActive = data.default_wan === wan.id;
            const div = document.getElementById("card-" + wan.id);

            // Keep DOM stable while hovered so tooltips can appear
            if (hoveredCards[wan.id]) {
                return;
            }

            const last = lastRenderedSpeeds[wan.id] || {};
            const downloadChanged = last.download_mbps !== wan.download_mbps;
            const uploadChanged = last.upload_mbps !== wan.upload_mbps;

            lastRenderedSpeeds[wan.id] = {
                download_mbps: wan.download_mbps,
                upload_mbps: wan.upload_mbps
            };

            const checkedAgo = wan.health_last_checked
                ? Math.max(0, Math.floor(Date.now() / 1000 - wan.health_last_checked))
                : "-";

            const ifaceText = (!wan.iface)
                ? "-"
                : (wan.iface_state ? `${wan.iface} (${String(wan.iface_state).toUpperCase()})` : wan.iface);

            const ifStats = (wan.iface_rx_dropped === null || wan.iface_rx_dropped === undefined
                || wan.iface_tx_dropped === null || wan.iface_tx_dropped === undefined
                || wan.iface_rx_errors === null || wan.iface_rx_errors === undefined
                || wan.iface_tx_errors === null || wan.iface_tx_errors === undefined)
                ? "-"
                : `Drop ${wan.iface_rx_dropped}/${wan.iface_tx_dropped} | Err ${wan.iface_rx_errors}/${wan.iface_tx_errors}`;

            div.innerHTML = `
                <div class="wan-title">${wan.id} - ${wan.name}</div>

                <div class="badges">
                    ${statusBadge(wan.iface_up, "Link")}
                    ${statusBadge(wan.gateway_online, "Gateway")}
                    ${statusBadge(wan.internet_online, "Internet")}
                    ${statusBadge(wan.internet_ir_online, "IR")}
                    <span class="badge ${isActive ? "active" : "standby"}" data-help="${isActive ? "default" : "standby"}">
                        ${isActive ? "DEFAULT" : "STANDBY"}
                    </span>
                </div>

                <div class="row">
                    <span class="help" data-help="sourceIp">Source IP</span>
                    <span class="value">${wan.source_ip}</span>
                </div>

                <div class="row">
                    <span class="help" data-help="gateway">Gateway</span>
                    <span class="value">${wan.gateway}</span>
                </div>

                <div class="row">
                    <span class="help" data-help="metric">Metric</span>
                    <span class="value">${wan.metric}</span>
                </div>

                <div class="row">
                    <span class="help" data-help="iface">Interface</span>
                    <span class="value">${ifaceText}</span>
                </div>

                <div class="row">
                    <span class="help" data-help="ifStats">IF Drop/Err (RX/TX)</span>
                    <span class="value">${ifStats}</span>
                </div>

                <div class="speed-grid">
                    <div class="speed-box ${downloadChanged ? "flash" : ""}">
                        <div class="speed-label">Download</div>
                        <div class="speed-value down">↓ ${wan.download_mbps.toFixed(2)} Mbps</div>
                    </div>

                    <div class="speed-box ${uploadChanged ? "flash" : ""}">
                        <div class="speed-label">Upload</div>
                        <div class="speed-value up">↑ ${wan.upload_mbps.toFixed(2)} Mbps</div>
                    </div>
                </div>

                <div class="row">
                    <span class="help" data-help="totals">Total Download</span>
                    <span class="value">${formatBytes(wan.download_total)}</span>
                </div>

                <div class="row">
                    <span class="help" data-help="totals">Total Upload</span>
                    <span class="value">${formatBytes(wan.upload_total)}</span>
                </div>

                <div class="row">
                    <span class="help" data-help="healthCheck">Health Check</span>
                    <span class="value">${checkedAgo}s ago</span>
                </div>

                <div class="row">
                    <span class="help" data-help="rttLoss">GW RTT / Loss</span>
                    <span class="value">${formatMs(wan.gateway_rtt_ms)} / ${formatPct(wan.gateway_loss_percent)}</span>
                </div>

                <div class="row">
                    <span class="help" data-help="jitter">GW Jitter</span>
                    <span class="value">${formatMs(wan.gateway_jitter_ms)}</span>
                </div>

                <div class="row">
                    <span class="help" data-help="rttLoss">NET RTT / Loss</span>
                    <span class="value">${formatMs(wan.internet_rtt_ms)} / ${formatPct(wan.internet_loss_percent)}</span>
                </div>

                <div class="row">
                    <span class="help" data-help="jitterTarget">NET Jitter / Target</span>
                    <span class="value">${formatMs(wan.internet_jitter_ms)} / ${(wan.internet_target || "-")}</span>
                </div>

                <div class="row">
                    <span class="help" data-help="rttLoss">IR RTT / Loss</span>
                    <span class="value">${formatMs(wan.internet_ir_rtt_ms)} / ${formatPct(wan.internet_ir_loss_percent)}</span>
                </div>

                <div class="row">
                    <span class="help" data-help="jitterTarget">IR Jitter / Target</span>
                    <span class="value">${formatMs(wan.internet_ir_jitter_ms)} / ${(wan.internet_ir_target || "-")}</span>
                </div>
            `;
        });
    }

    function pushHistory(data) {
        if (history.length && history[history.length - 1].timestamp === data.timestamp) {
            history[history.length - 1] = data;
        } else {
            history.push(data);
        }

        if (history.length > maxPoints) {
            history.shift();
        }
    }

    function drawChart(canvasId, field) {
        const canvas = document.getElementById(canvasId);
        const rect = canvas.getBoundingClientRect();

        const dpr = window.devicePixelRatio || 1;
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;

        const ctx = canvas.getContext("2d");
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        const width = rect.width;
        const height = rect.height;
        const padding = 35;

        ctx.clearRect(0, 0, width, height);

        ctx.strokeStyle = "#1e293b";
        ctx.lineWidth = 1;

        for (let i = 0; i <= 5; i++) {
            const y = padding + ((height - padding * 2) / 5) * i;
            ctx.beginPath();
            ctx.moveTo(padding, y);
            ctx.lineTo(width - padding, y);
            ctx.stroke();
        }

        let maxValue = 1;

        history.forEach(point => {
            point.wans.forEach(wan => {
                if (wan[field] > maxValue) {
                    maxValue = wan[field];
                }
            });
        });

        maxValue = Math.ceil(maxValue + 1);

        ctx.fillStyle = "#94a3b8";
        ctx.font = "12px Arial";
        ctx.fillText(maxValue + " Mbps", 8, padding);
        ctx.fillText("0", 18, height - padding);

        const wanIds = wanOrder.length ? wanOrder : [];

        wanIds.forEach(wanId => {
            ctx.strokeStyle = colorForWan(wanId);
            ctx.lineWidth = 2;
            ctx.beginPath();

            let started = false;

            history.forEach((point, index) => {
                const wan = point.wans.find(x => x.id === wanId);
                if (!wan) return;

                const value = wan[field];
                const x = padding + ((width - padding * 2) / Math.max(maxPoints - 1, 1)) * index;
                const y = height - padding - ((value / maxValue) * (height - padding * 2));

                if (!started) {
                    ctx.moveTo(x, y);
                    started = true;
                } else {
                    ctx.lineTo(x, y);
                }
            });

            ctx.stroke();
        });

        let legendX = padding;
        const legendY = height - 8;

        wanIds.forEach(wanId => {
            ctx.fillStyle = colorForWan(wanId);
            ctx.fillRect(legendX, legendY - 9, 10, 10);

            ctx.fillStyle = "#e5e7eb";
            ctx.fillText(wanId, legendX + 14, legendY);

            legendX += 75;
        });
    }

    async function loadRoutes() {
        try {
            const response = await fetch("/api/routes?t=" + Date.now(), { cache: "no-store" });
            const data = await response.json();
            document.getElementById("routesBox").innerText = data.output || "No output";
        } catch (e) {
            document.getElementById("routesBox").innerText = "Routes fetch error: " + e;
        }
    }

    loadStatus();
    setInterval(loadStatus, 1000);

    // default tab
    setTab("wan");

    window.addEventListener("resize", () => {
        if (currentTab === "wan") {
            drawChart("downloadCanvas", "download_mbps");
            drawChart("uploadCanvas", "upload_mbps");
        }
    });
</script>
</body>
</html>
"""

if __name__ == "__main__":
    speed_thread = threading.Thread(target=speed_collector_loop, daemon=True)
    health_thread = threading.Thread(target=health_collector_loop, daemon=True)

    speed_thread.start()
    health_thread.start()

    app.run(host=BIND_HOST, port=PORT, debug=False, use_reloader=False, threaded=True)
