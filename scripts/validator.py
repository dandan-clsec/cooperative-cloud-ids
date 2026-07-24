#!/usr/bin/env python3
"""
validator.py - Cooperative OR-Merge alert validation & accuracy scoring for the
Cooperative Cloud IDS Framework.

Implements the exact scoring model from the study:

    TP : an injected attack event has a matching alert in EITHER
         Snort OR Suricata (the cooperative OR-merge).
    FN : an injected attack event has no matching alert in either engine.
    FP : an alert exists that does not correspond to any injected event.

    Accuracy = TP / (TP + FP + FN) * 100

It parses:
    * Snort   : alert_fast.txt  (single-line "[**] ... [**] msg ...")
                and/or alert_json.txt (one JSON object per line)
    * Suricata: eve.json        (one JSON event per line, type == "alert")
                and/or suricata.log (fast.log text format)

Usage:
    python3 validator.py --results-dir ../results/cooperative_dos_2026...
    python3 validator.py \
        --snort  ../logs/snort/alert_fast.txt \
        --suricata ../logs/suricata/eve.json \
        --ground-truth ground_truth.json \
        --condition cooperative
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


# --------------------------------------------------------------------------- #
# Alert model
# --------------------------------------------------------------------------- #
@dataclass
class Alert:
    engine: str          # "snort" | "suricata"
    msg: str             # human-readable signature message
    sid: int | None      # rule id, if available
    src: str | None = None
    dst: str | None = None
    dport: int | None = None
    raw: str = ""


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
# Snort 3 alert_fast line, e.g.:
# 07/08-12:00:01.123456 [**] [1:1000010:2] "COOP-IDS SQL Injection UNION
#   SELECT" [**] [Classification: ...] [Priority: 1] {TCP} 1.2.3.4:5 -> 6.7.8.9:8080
SNORT_FAST_RE = re.compile(
    r"\[\*\*\]\s*\[\d+:(?P<sid>\d+):\d+\]\s*\"?(?P<msg>[^\"]+?)\"?\s*\[\*\*\]"
    r".*?\{(?P<proto>\w+)\}\s*(?P<src>[\d.]+):?(?P<sport>\d+)?\s*->\s*"
    r"(?P<dst>[\d.]+):?(?P<dport>\d+)?",
    re.IGNORECASE,
)

# Suricata fast.log line, e.g.:
# 07/08/2026-12:00:01.123456  [**] [1:1000010:2] COOP-IDS SQL Injection ...
#   [**] [Classification: ...] [Priority: 1] {TCP} 1.2.3.4:5 -> 6.7.8.9:8080
SURICATA_FAST_RE = SNORT_FAST_RE  # identical fast.log grammar


def parse_snort_fast(path: Path) -> list[Alert]:
    alerts: list[Alert] = []
    if not path.exists():
        return alerts
    for line in path.read_text(errors="ignore").splitlines():
        m = SNORT_FAST_RE.search(line)
        if not m:
            continue
        alerts.append(Alert(
            engine="snort",
            msg=m.group("msg").strip(),
            sid=int(m.group("sid")),
            src=m.group("src"),
            dst=m.group("dst"),
            dport=int(m.group("dport")) if m.group("dport") else None,
            raw=line.strip(),
        ))
    return alerts


def parse_snort_json(path: Path) -> list[Alert]:
    alerts: list[Alert] = []
    if not path.exists():
        return alerts
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        alerts.append(Alert(
            engine="snort",
            msg=str(obj.get("msg", "")),
            sid=_to_int(obj.get("sid")),
            src=obj.get("src_addr"),
            dst=obj.get("dst_addr"),
            dport=_to_int(obj.get("dst_port")),
            raw=line,
        ))
    return alerts


def parse_suricata_eve(path: Path) -> list[Alert]:
    alerts: list[Alert] = []
    if not path.exists():
        return alerts
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("event_type") != "alert":
            continue
        sig = obj.get("alert", {})
        alerts.append(Alert(
            engine="suricata",
            msg=str(sig.get("signature", "")),
            sid=_to_int(sig.get("signature_id")),
            src=obj.get("src_ip"),
            dst=obj.get("dest_ip"),
            dport=_to_int(obj.get("dest_port")),
            raw=line,
        ))
    return alerts


def parse_suricata_fast(path: Path) -> list[Alert]:
    alerts: list[Alert] = []
    if not path.exists():
        return alerts
    for line in path.read_text(errors="ignore").splitlines():
        m = SURICATA_FAST_RE.search(line)
        if not m:
            continue
        alerts.append(Alert(
            engine="suricata",
            msg=m.group("msg").strip(),
            sid=int(m.group("sid")),
            src=m.group("src"),
            dst=m.group("dst"),
            dport=int(m.group("dport")) if m.group("dport") else None,
            raw=line.strip(),
        ))
    return alerts


def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Matching logic
# --------------------------------------------------------------------------- #
def alert_matches_event(alert: Alert, event: dict) -> bool:
    """
    An alert matches an injected attack event when either:
      * its SID is one of the event's expected SIDs, OR
      * one of the event's signature keywords appears in the alert message
    and (when known) the destination port lines up with the event's target.
    """
    # SID match (strongest signal).
    if alert.sid is not None and alert.sid in set(event.get("sids", [])):
        return _port_ok(alert, event)

    # Keyword / signature-text match.
    msg = alert.msg.lower()
    for kw in event.get("signatures", []):
        if kw.lower() in msg:
            return _port_ok(alert, event)
    return False


def _port_ok(alert: Alert, event: dict) -> bool:
    exp = event.get("dst_port")
    if exp is None or alert.dport is None:
        return True  # can't disprove; accept
    return alert.dport == exp


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    detected_events: list[str] = field(default_factory=list)
    missed_events: list[str] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        denom = self.tp + self.fp + self.fn
        return round(self.tp / denom * 100.0, 2) if denom else 0.0


def score(condition: str, ground_truth: dict,
          snort_alerts: list[Alert],
          suricata_alerts: list[Alert]) -> Score:
    """
    Build the engine alert pool for the given condition, then apply the
    OR-merge: an event counts as a TP if ANY alert in the active pool matches.
    """
    if condition == "snort_only":
        pool = list(snort_alerts)
    elif condition == "suricata_only":
        pool = list(suricata_alerts)
    else:  # cooperative (and baseline, which should yield no attack matches)
        pool = list(snort_alerts) + list(suricata_alerts)

    s = Score()
    matched_alert_ids: set[int] = set()

    # --- True positives / False negatives (per injected attack event) --------
    for event in ground_truth.get("events", []):
        hit = False
        for idx, alert in enumerate(pool):
            if alert_matches_event(alert, event):
                hit = True
                matched_alert_ids.add(idx)
        if hit:
            s.tp += 1
            s.detected_events.append(event["id"])
        else:
            s.fn += 1
            s.missed_events.append(event["id"])

    # --- False positives (alerts that matched no injected event) -------------
    # Any alert never attributed to a ground-truth event is spurious.
    for idx, _alert in enumerate(pool):
        if idx not in matched_alert_ids:
            s.fp += 1

    return s


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def report(condition: str, s: Score,
           n_snort: int, n_suricata: int) -> None:
    bar = "=" * 60
    print(bar)
    print(f" COOPERATIVE IDS - DETECTION VALIDATION ({condition})")
    print(bar)
    print(f"  Snort alerts parsed    : {n_snort}")
    print(f"  Suricata alerts parsed : {n_suricata}")
    print("-" * 60)
    print(f"  True Positives  (TP)   : {s.tp}")
    print(f"  False Positives (FP)   : {s.fp}")
    print(f"  False Negatives (FN)   : {s.fn}")
    print("-" * 60)
    print(f"  Detected events        : {', '.join(s.detected_events) or '-'}")
    print(f"  Missed events          : {', '.join(s.missed_events) or '-'}")
    print("-" * 60)
    print(f"  Accuracy = TP / (TP+FP+FN) * 100")
    print(f"           = {s.tp} / ({s.tp}+{s.fp}+{s.fn}) * 100")
    print(f"           = {s.accuracy}%")
    print(bar)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    p = argparse.ArgumentParser(description="Cooperative OR-merge validator")
    p.add_argument("--condition",
                   choices=("snort_only", "suricata_only", "cooperative",
                            "baseline"),
                   default="cooperative")
    p.add_argument("--ground-truth",
                   default=str(BASE_DIR / "ground_truth.json"))
    p.add_argument("--results-dir",
                   help="trial dir containing collected log snapshots")
    p.add_argument("--snort", help="path to snort alert_fast.txt")
    p.add_argument("--snort-json", help="path to snort alert_json.txt")
    p.add_argument("--suricata", help="path to suricata eve.json")
    p.add_argument("--suricata-fast", help="path to suricata.log (fast.log)")
    p.add_argument("--json", action="store_true",
                   help="emit machine-readable JSON summary")
    args = p.parse_args()

    ground_truth = json.loads(Path(args.ground_truth).read_text())

    # Resolve log paths, preferring an explicit --results-dir snapshot.
    if args.results_dir:
        rd = Path(args.results_dir)
        snort_fast = rd / "alert_fast.txt"
        snort_json = rd / "alert_json.txt"
        suri_eve = rd / "eve.json"
        suri_fast = rd / "suricata.log"
    else:
        root = BASE_DIR.parent
        snort_fast = Path(args.snort) if args.snort else root / "logs/snort/alert_fast.txt"
        snort_json = Path(args.snort_json) if args.snort_json else root / "logs/snort/alert_json.txt"
        suri_eve = Path(args.suricata) if args.suricata else root / "logs/suricata/eve.json"
        suri_fast = Path(args.suricata_fast) if args.suricata_fast else root / "logs/suricata/suricata.log"

    # Parse everything available and de-duplicate per engine.
    snort_alerts = parse_snort_fast(snort_fast) or parse_snort_json(snort_json)
    suricata_alerts = parse_suricata_eve(suri_eve) or parse_suricata_fast(suri_fast)

    s = score(args.condition, ground_truth, snort_alerts, suricata_alerts)

    if args.json:
        print(json.dumps({
            "condition": args.condition,
            "true_positives": s.tp,
            "false_positives": s.fp,
            "false_negatives": s.fn,
            "accuracy_pct": s.accuracy,
            "detected_events": s.detected_events,
            "missed_events": s.missed_events,
            "snort_alerts": len(snort_alerts),
            "suricata_alerts": len(suricata_alerts),
        }, indent=2))
    else:
        report(args.condition, s, len(snort_alerts), len(suricata_alerts))

    return 0


if __name__ == "__main__":
    sys.exit(main())
