#!/usr/bin/env python3
"""
dashboard.py - Web control panel for the Cooperative Cloud IDS Framework.

A single Flask app that gives the whole framework a GUI:
  * live container / service status (LocalStack, target, engines, Prometheus)
  * one-click trial execution (baseline / snort_only / suricata_only /
    cooperative x dos / sqli / bruteforce) via orchestrator.py
  * OR-merge validation via validator.py with TP/FP/FN/accuracy readout
  * live CPU / memory / packet-loss telemetry from Prometheus + trial bundles
  * results history table across all recorded trials

Run:
    pip install flask requests            # (requests optional)
    python3 gui/dashboard.py
    open http://localhost:5000

The dashboard shells out to the existing scripts so there is a single source
of truth for trial logic. Long-running trials are launched as background jobs
and streamed to the browser via a simple polling API.
"""

import json
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request, Response

# --------------------------------------------------------------------------- #
# Paths / config
# --------------------------------------------------------------------------- #
BASE_DIR = Path(__file__).resolve().parent.parent          # cooperative-ids/
SCRIPTS = BASE_DIR / "scripts"
RESULTS_DIR = BASE_DIR / "results"
ORCHESTRATOR = SCRIPTS / "orchestrator.py"
VALIDATOR = SCRIPTS / "validator.py"
GROUND_TRUTH = SCRIPTS / "ground_truth.json"

PROMETHEUS_URL = "http://localhost:9090"

CONTAINERS = {
    "LocalStack": "ids_localstack",
    "Target (DVWA+SSH)": "ids_target",
    "Snort 3": "ids_snort",
    "Suricata 7": "ids_suricata",
    "Node Exporter": "ids_node_exporter",
    "Prometheus": "ids_prometheus",
}

CONDITIONS = ["baseline", "snort_only", "suricata_only", "cooperative"]
ATTACKS = ["dos", "sqli", "bruteforce"]

app = Flask(__name__)

# In-memory job registry: job_id -> {status, log[], returncode, meta}
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def sh(cmd: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def container_status() -> list[dict]:
    """Return running/exited/absent state + basic stats per known container."""
    out = []
    # One docker ps call, parse the lot.
    try:
        ps = sh(["docker", "ps", "-a", "--format",
                 "{{.Names}}|{{.State}}|{{.Status}}"])
        rows = {}
        for line in ps.stdout.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 3:
                rows[parts[0]] = {"state": parts[1], "status": parts[2]}
    except Exception as e:                       # noqa: BLE001
        rows = {}
    for label, cname in CONTAINERS.items():
        info = rows.get(cname)
        if info is None:
            out.append({"name": label, "container": cname,
                        "state": "absent", "status": "not created"})
        else:
            out.append({"name": label, "container": cname,
                        "state": info["state"], "status": info["status"]})
    return out


def prometheus_instant(expr: str):
    """Single-value instant query against Prometheus."""
    import urllib.parse
    import urllib.request
    url = f"{PROMETHEUS_URL}/api/v1/query?" + urllib.parse.urlencode(
        {"query": expr})
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.load(r)
        res = data["data"]["result"]
        if res:
            return round(float(res[0]["value"][1]), 2)
    except Exception:                            # noqa: BLE001
        return None
    return None


def live_metrics() -> dict:
    cpu = prometheus_instant(
        '100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[1m])) * 100)')
    mem = prometheus_instant(
        '(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes)'
        '/1024/1024')
    mem_total = prometheus_instant('node_memory_MemTotal_bytes/1024/1024')
    return {
        "cpu_pct": cpu,
        "mem_mb": mem,
        "mem_total_mb": mem_total,
        "prometheus_up": cpu is not None,
    }


def list_results() -> list[dict]:
    """Read every telemetry.json bundle and any validation result."""
    rows = []
    if not RESULTS_DIR.exists():
        return rows
    for d in sorted(RESULTS_DIR.iterdir(), reverse=True):
        tel = d / "telemetry.json"
        if not tel.exists():
            continue
        try:
            bundle = json.loads(tel.read_text())
        except Exception:                        # noqa: BLE001
            continue
        val = d / "validation.json"
        validation = None
        if val.exists():
            try:
                validation = json.loads(val.read_text())
            except Exception:                    # noqa: BLE001
                validation = None
        rows.append({
            "dir": d.name,
            "condition": bundle.get("condition"),
            "attack": bundle.get("attack"),
            "cpu": bundle.get("resource", {}).get("avg_cpu_pct"),
            "mem": bundle.get("resource", {}).get("avg_memory_mb"),
            "loss": bundle.get("packets", {}).get("loss_rate_pct"),
            "seen": bundle.get("packets", {}).get("packets_seen"),
            "accuracy": validation.get("accuracy_pct") if validation else None,
            "tp": validation.get("true_positives") if validation else None,
            "fp": validation.get("false_positives") if validation else None,
            "fn": validation.get("false_negatives") if validation else None,
        })
    return rows


# --------------------------------------------------------------------------- #
# Background job runner
# --------------------------------------------------------------------------- #
def run_job(job_id: str, cmd: list[str], on_done=None) -> None:
    with JOBS_LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["log"].append(f"[{now()}] $ {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd, cwd=str(BASE_DIR),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                bufsize=1)
        for line in proc.stdout:                 # stream output
            with JOBS_LOCK:
                JOBS[job_id]["log"].append(line.rstrip())
        proc.wait()
        rc = proc.returncode
    except Exception as e:                       # noqa: BLE001
        with JOBS_LOCK:
            JOBS[job_id]["log"].append(f"[error] {e}")
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["returncode"] = 1
        return
    with JOBS_LOCK:
        JOBS[job_id]["returncode"] = rc
        JOBS[job_id]["status"] = "done" if rc == 0 else "error"
        JOBS[job_id]["log"].append(f"[{now()}] exited with code {rc}")
    if on_done:
        on_done(job_id, rc)


def new_job(meta: dict) -> str:
    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {"status": "queued", "log": [],
                        "returncode": None, "meta": meta}
    return job_id


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return render_template("index.html",
                           conditions=CONDITIONS, attacks=ATTACKS)


@app.route("/api/status")
def api_status():
    return jsonify({
        "containers": container_status(),
        "metrics": live_metrics(),
        "time": now(),
    })


@app.route("/api/results")
def api_results():
    return jsonify(list_results())


@app.route("/api/ground_truth")
def api_ground_truth():
    try:
        return jsonify(json.loads(GROUND_TRUTH.read_text()))
    except Exception as e:                       # noqa: BLE001
        return jsonify({"error": str(e)}), 500


@app.route("/api/compose", methods=["POST"])
def api_compose():
    """Bring the stack up or down."""
    action = request.json.get("action", "up")
    if action == "up":
        cmd = ["docker", "compose", "up", "-d"]
    elif action == "down":
        cmd = ["docker", "compose", "down"]
    else:
        return jsonify({"error": "bad action"}), 400
    job_id = new_job({"kind": "compose", "action": action})
    threading.Thread(target=run_job, args=(job_id, cmd), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/mirror", methods=["POST"])
def api_mirror():
    """(Re)install the tc kernel mirror. Needs sudo on the host."""
    cmd = ["sudo", str(SCRIPTS / "mirror_setup.sh")]
    job_id = new_job({"kind": "mirror"})
    threading.Thread(target=run_job, args=(job_id, cmd), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/trial", methods=["POST"])
def api_trial():
    """Launch an orchestrator trial, then auto-validate when it finishes."""
    body = request.json or {}
    condition = body.get("condition")
    attack = body.get("attack")
    duration = int(body.get("duration", 120))

    if condition not in CONDITIONS:
        return jsonify({"error": "invalid condition"}), 400
    if condition != "baseline" and attack not in ATTACKS:
        return jsonify({"error": "attack required for this condition"}), 400

    cmd = ["python3", str(ORCHESTRATOR), "--condition", condition]
    if condition != "baseline":
        cmd += ["--attack", attack, "--duration", str(duration)]

    job_id = new_job({"kind": "trial", "condition": condition,
                      "attack": attack})

    def after_trial(jid: str, rc: int):
        """On success, find the newest matching result dir and validate it."""
        if rc != 0 or condition == "baseline":
            return
        prefix = f"{condition}_{attack}_"
        dirs = sorted([d for d in RESULTS_DIR.glob(prefix + "*")
                       if d.is_dir()], reverse=True)
        if not dirs:
            return
        latest = dirs[0]
        with JOBS_LOCK:
            JOBS[jid]["log"].append(f"[{now()}] validating {latest.name}")
        vout = sh(["python3", str(VALIDATOR), "--condition", condition,
                   "--results-dir", str(latest), "--json"], timeout=60)
        (latest / "validation.json").write_text(vout.stdout)
        with JOBS_LOCK:
            JOBS[jid]["log"].append(vout.stdout.strip())

    threading.Thread(target=run_job, args=(job_id, cmd),
                     kwargs={"on_done": after_trial}, daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/validate", methods=["POST"])
def api_validate():
    """Manually (re)validate an existing results dir."""
    body = request.json or {}
    dirname = body.get("dir")
    condition = body.get("condition", "cooperative")
    target = RESULTS_DIR / dirname
    if not target.exists():
        return jsonify({"error": "results dir not found"}), 404
    vout = sh(["python3", str(VALIDATOR), "--condition", condition,
               "--results-dir", str(target), "--json"], timeout=60)
    try:
        parsed = json.loads(vout.stdout)
        (target / "validation.json").write_text(vout.stdout)
        return jsonify(parsed)
    except Exception:                            # noqa: BLE001
        return jsonify({"error": "validation failed",
                        "raw": vout.stdout + vout.stderr}), 500


@app.route("/api/job/<job_id>")
def api_job(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "unknown job"}), 404
        return jsonify({
            "status": job["status"],
            "returncode": job["returncode"],
            "log": job["log"][-400:],
            "meta": job["meta"],
        })


if __name__ == "__main__":
    RESULTS_DIR.mkdir(exist_ok=True)
    print("Cooperative IDS dashboard -> http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
