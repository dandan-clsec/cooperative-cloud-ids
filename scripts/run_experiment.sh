#!/bin/bash
# =============================================================================
# run_experiment.sh - Full experiment sweep across the four conditions and
# three attack types, three trials each, then validate every trial.
#
# Assumes the stack is already up (docker compose up -d) and mirror_setup.sh
# has been run on the host.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PY="python3"
TRIALS="${TRIALS:-3}"
DURATION="${DURATION:-120}"

CONDITIONS=(snort_only suricata_only cooperative)
ATTACKS=(dos sqli bruteforce)

echo "[experiment] baseline control run"
"${PY}" "${HERE}/orchestrator.py" --condition baseline

for cond in "${CONDITIONS[@]}"; do
  for atk in "${ATTACKS[@]}"; do
    for t in $(seq 1 "${TRIALS}"); do
      echo "[experiment] ${cond} / ${atk} / trial ${t}"
      "${PY}" "${HERE}/orchestrator.py" \
        --condition "${cond}" --attack "${atk}" --duration "${DURATION}"
      echo "[experiment] validating latest ${cond}/${atk} trial"
      latest="$(ls -dt "${HERE}/../results/${cond}_${atk}_"* | head -1)"
      "${PY}" "${HERE}/validator.py" \
        --condition "${cond}" --results-dir "${latest}" --json
    done
  done
done

echo "[experiment] sweep complete. See results/ for per-trial telemetry."
