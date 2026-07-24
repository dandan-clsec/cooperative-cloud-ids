#!/usr/bin/env python3
"""
orchestrator.py - Automated trial execution engine for the Cooperative Cloud
IDS Framework.

Runs a single trial end-to-end and produces a telemetry bundle:
  * starts tcpdump on the bridge + container interfaces (Packets Seen / Dropped)
  * for a 'baseline' run, drives 10 minutes of benign HTTP traffic
  * for active runs (snort_only | suricata_only | cooperative), isolates the
    relevant engine container(s) and lets the operator launch the attack
  * pulls CPU / memory time-series averages from the Prometheus HTTP API
  * collects snort.log and suricata.log alert streams

The actual adversarial payloads (hping3 / sqlmap / hydra) are launched from the
separate Kali attacker node; this orchestrator manages the *measurement* window
and, for convenience, can fire the attack over SSH if --attacker-exec is given.

Usage:
    python3 orchestrator.py --condition cooperative --attack dos
    python3 orchestrator.py --condition baseline
    python3 orchestrator.py --condition snort_only --attack sqli --duration 120

Requires: docker CLI, tcpdump, requests (pip install requests).
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import urllib.request
import urllib.parse

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
TARGET_IP = os.environ.get("TARGET_IP", "172.20.0.20")
TARGET_HTTP = f"http://localhost:8090"          # host-published DVWA port
BRIDGE_IFACE = os.environ.get("BRIDGE_IFACE", "")   # auto-resolved if empty
NETWORK_NAME = "ids_net"

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_SNORT = BASE_DIR / "logs" / "snort"
LOG_SURICATA = BASE_DIR / "logs" / "suricata"
RESULTS_DIR = BASE_DIR / "results"

BASELINE_SECONDS = 600      # 10-minute control window
DEFAULT_TRIAL_SECONDS = 120

VALID_CONDITIONS = ("baseline", "snort_only", "suricata_only", "cooperative")
VALID_ATTACKS = ("dos", "sqli", "bruteforce")


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[orchestrator {ts}] {msg}", flush=True)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def run(cmd, **kw):
    """Run a command, returning CompletedProcess; never raises on non-zero."""
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def resolve_bridge_iface() -> str:
    """Resolve host bridge interface (br-<netid[:12]>) for ids_net."""
    if BRIDGE_IFACE:
        return BRIDGE_IFACE
    res = run(["docker", "network", "inspect", "-f", "{{.Id}}", NETWORK_NAME])
    if res.returncode != 0:
        log("WARN: could not resolve ids_net; falling back to 'docker0'")
        return "docker0"
    netid = res.stdout.strip()
    return f"br-{netid[:12]}"


def set_engine_state(condition: str) -> None:
    """
    Isolate engine processes per condition by starting/stopping the relevant
    detection containers. The mirror keeps feeding both veths regardless; the
    condition simply decides which engine is actually running.
    """
    want_snort = condition in ("snort_only", "cooperative")
    want_suricata = condition in ("suricata_only", "cooperative")
    # baseline => neither engine runs (pure environment overhead).

    for name, want in (("ids_snort", want_snort), ("ids_suricata", want_suricata)):
        action = "start" if want else "stop"
        log(f"{action}ing {name}")
        run(["docker", action, name])
    # Give engines a moment to attach to the interface.
    if want_snort or want_suricata:
        time.sleep(5)


def start_tcpdump(iface: str, out_pcap: Path) -> subprocess.Popen:
    """Start a background tcpdump counting packets on the given interface."""
    log(f"starting tcpdump on {iface} -> {out_pcap.name}")
    # -w to file so we can count precisely; -q quiet; run privileged if needed.
    proc = subprocess.Popen(
        ["tcpdump", "-i", iface, "-w", str(out_pcap), "-U", "-q"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    return proc


def stop_tcpdump(proc: subprocess.Popen) -> dict:
    """Stop tcpdump and parse its 'N packets received/dropped' summary."""
    proc.send_signal(signal.SIGINT)
    try:
        _, stderr = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, stderr = proc.communicate()
    seen = dropped_kernel = dropped_iface = 0
    for line in (stderr or "").splitlines():
        line = line.strip()
        if line.endswith("packets captured"):
            seen = int(line.split()[0])
        elif "packets received by filter" in line:
            # informational; keep 'seen' from 'captured'
            pass
        elif "packets dropped by kernel" in line:
            dropped_kernel = int(line.split()[0])
        elif "packets dropped by interface" in line:
            dropped_iface = int(line.split()[0])
    dropped = dropped_kernel + dropped_iface
    total = seen + dropped
    loss = (dropped / total * 100.0) if total else 0.0
    return {
        "packets_seen": seen,
        "packets_dropped": dropped,
        "loss_rate_pct": round(loss, 2),
    }


def prometheus_query(expr: str, start: float, end: float, step: int = 5):
    """Query the Prometheus range API and return the raw result series."""
    params = urllib.parse.urlencode({
        "query": expr, "start": start, "end": end, "step": step,
    })
    url = f"{PROMETHEUS_URL}/api/v1/query_range?{params}"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            payload = json.load(r)
    except Exception as e:               # noqa: BLE001 - report and continue
        log(f"WARN: Prometheus query failed: {e}")
        return []
    if payload.get("status") != "success":
        return []
    return payload["data"]["result"]


def average_series(result) -> float:
    """Average all sample values across the returned series."""
    vals = []
    for series in result:
        for _, v in series.get("values", []):
            try:
                vals.append(float(v))
            except ValueError:
                continue
    return round(sum(vals) / len(vals), 2) if vals else 0.0


def collect_metrics(start: float, end: float) -> dict:
    """Pull averaged CPU % and memory (MB) for VM1 over the trial window."""
    # CPU busy % = 100 - idle%, averaged over 30s rate windows.
    cpu_expr = (
        '100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[30s])) * 100)'
    )
    mem_expr = (
        '(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) '
        '/ 1024 / 1024'
    )
    cpu = average_series(prometheus_query(cpu_expr, start, end))
    mem = average_series(prometheus_query(mem_expr, start, end))
    return {"avg_cpu_pct": cpu, "avg_memory_mb": mem}


def benign_traffic(duration_s: int) -> None:
    """Simulate normal user interaction with DVWA for the baseline window."""
    log(f"generating benign HTTP traffic for {duration_s}s")
    end = time.time() + duration_s
    pages = ["/", "/login.php", "/index.php", "/about.php",
             "/dvwa/images/login_logo.png"]
    i = 0
    while time.time() < end:
        url = TARGET_HTTP + pages[i % len(pages)]
        try:
            urllib.request.urlopen(url, timeout=3).read()
        except Exception:                # noqa: BLE001 - target may 302/404
            pass
        i += 1
        time.sleep(1)
    log(f"benign traffic complete ({i} requests)")


def launch_attack_hint(attack: str) -> None:
    """Print the exact command to run from the Kali attacker (VM2)."""
    gt = json.loads((BASE_DIR / "scripts" / "ground_truth.json").read_text())
    ev = next((e for e in gt["events"] if e["attack_type"] == attack), None)
    if ev:
        log("=" * 60)
        log(f"RUN THIS ATTACK FROM THE KALI NODE (VM2) NOW:")
        log(f"    {ev['command']}")
        log("=" * 60)


def snapshot_logs(dest: Path) -> None:
    """Copy the current engine alert logs into the trial results directory."""
    dest.mkdir(parents=True, exist_ok=True)
    for src in (LOG_SNORT / "alert_fast.txt",
                LOG_SNORT / "alert_json.txt",
                LOG_SURICATA / "suricata.log",
                LOG_SURICATA / "eve.json"):
        if src.exists():
            shutil.copy2(src, dest / src.name)
            log(f"collected {src.name}")


# --------------------------------------------------------------------------- #
# Trial driver
# --------------------------------------------------------------------------- #
def run_trial(condition: str, attack: str | None, duration: int,
              has_tcpdump: bool = True) -> dict:
    iface = resolve_bridge_iface()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    trial_dir = RESULTS_DIR / f"{condition}_{attack or 'benign'}_{stamp}"
    trial_dir.mkdir(parents=True, exist_ok=True)
    pcap = trial_dir / "capture.pcap"

    log(f"=== TRIAL START: condition={condition} attack={attack} ===")

    # 1. Engine isolation for this condition.
    set_engine_state(condition)

    # 2. Start packet capture + record window start.
    start_ts = time.time()
    tcpdump_proc = None
    if has_tcpdump:
        tcpdump_proc = start_tcpdump(iface, pcap)
        time.sleep(2)  # let tcpdump attach

    # 3. Drive the workload.
    if condition == "baseline":
        benign_traffic(BASELINE_SECONDS)
    else:
        if attack:
            launch_attack_hint(attack)
        log(f"trial window open for {duration}s "
            f"(launch/allow the attack to run)")
        time.sleep(duration)

    end_ts = time.time()

    # 4. Stop capture + gather telemetry.
    if tcpdump_proc is not None:
        packet_stats = stop_tcpdump(tcpdump_proc)
    else:
        log("WARN: tcpdump unavailable — packet stats will be zeroed")
        packet_stats = {"packets_seen": 0, "packets_dropped": 0, "loss_rate_pct": 0.0}
    time.sleep(6)  # allow final Prometheus scrape to land
    metrics = collect_metrics(start_ts, end_ts)
    snapshot_logs(trial_dir)

    bundle = {
        "condition": condition,
        "attack": attack,
        "start_utc": datetime.fromtimestamp(start_ts, timezone.utc).isoformat(),
        "end_utc": datetime.fromtimestamp(end_ts, timezone.utc).isoformat(),
        "duration_s": round(end_ts - start_ts, 1),
        "interface": iface,
        "resource": metrics,
        "packets": packet_stats,
        "results_dir": str(trial_dir),
    }
    (trial_dir / "telemetry.json").write_text(json.dumps(bundle, indent=2))
    log(f"telemetry bundle written -> {trial_dir/'telemetry.json'}")
    log("=== TRIAL END ===")
    print(json.dumps(bundle, indent=2))
    return bundle


def main() -> int:
    p = argparse.ArgumentParser(description="Cooperative IDS trial orchestrator")
    p.add_argument("--condition", required=True, choices=VALID_CONDITIONS)
    p.add_argument("--attack", choices=VALID_ATTACKS,
                   help="required for non-baseline conditions")
    p.add_argument("--duration", type=int, default=DEFAULT_TRIAL_SECONDS,
                   help="active trial window in seconds (ignored for baseline)")
    args = p.parse_args()

    if args.condition != "baseline" and not args.attack:
        p.error("--attack is required unless --condition baseline")

    # docker is mandatory; tcpdump is optional (not available on Windows —
    # packet-capture stats will be zeroed but all other telemetry still works).
    if shutil.which("docker") is None:
        log("ERROR: required tool 'docker' not found in PATH")
        return 1

    has_tcpdump = shutil.which("tcpdump") is not None
    if not has_tcpdump:
        log("WARN: 'tcpdump' not found — packet capture disabled. "
            "Install Npcap + WinDump for packet stats on Windows, "
            "or run via WSL2 for full functionality.")

    run_trial(args.condition, args.attack, args.duration,
              has_tcpdump=has_tcpdump)
    return 0


if __name__ == "__main__":
    sys.exit(main())
