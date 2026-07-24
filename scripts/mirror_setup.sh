#!/bin/bash
# =============================================================================
# mirror_setup.sh - Kernel-level traffic mirroring for the Cooperative IDS
# -----------------------------------------------------------------------------
# Uses Linux Traffic Control (tc) with the mirred action to duplicate 100% of
# the traffic reaching the target container to BOTH detection engines
# simultaneously. This is what makes the framework "cooperative" rather than a
# competitive race: neither engine consumes the packet; each gets an identical
# copy, and the original still reaches the target.
#
# Run this on the DOCKER HOST (the VM running the daemon), NOT inside a
# container, because it manipulates the veth interfaces on the host side of the
# ids_net bridge.
#
#   sudo ./mirror_setup.sh
#   sudo ./mirror_setup.sh --teardown
# =============================================================================
set -euo pipefail

# ---- Configuration ----------------------------------------------------------
BRIDGE="${BRIDGE_IFACE:-br-}"          # docker bridge prefix; resolved below
NETWORK_NAME="ids_net"
TARGET_CONTAINER="ids_target"
SNORT_CONTAINER="ids_snort"
SURICATA_CONTAINER="ids_suricata"

log() { echo -e "[mirror] $*"; }
die() { echo "[mirror][ERROR] $*" >&2; exit 1; }

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "must run as root (use sudo)"
}

# Resolve the host-side bridge interface that backs the ids_net docker network.
resolve_bridge() {
  local netid
  netid="$(docker network inspect -f '{{.Id}}' "${NETWORK_NAME}" 2>/dev/null)" \
    || die "docker network '${NETWORK_NAME}' not found. Run 'docker compose up -d' first."
  # Docker names bridge interfaces br-<first 12 chars of network id>.
  BRIDGE="br-${netid:0:12}"
  ip link show "${BRIDGE}" >/dev/null 2>&1 \
    || die "bridge interface ${BRIDGE} not present on host"
  log "resolved ids_net bridge -> ${BRIDGE}"
}

# Resolve the host-side veth peer for a given container's eth0.
# Returns the host veth ifname via the iflink/ifindex pairing.
host_veth_for() {
  local container="$1"
  local pid iflink veth
  pid="$(docker inspect -f '{{.State.Pid}}' "${container}")" \
    || die "container ${container} not running"
  # ifindex of eth0 inside the container namespace.
  iflink="$(nsenter -t "${pid}" -n cat /sys/class/net/eth0/iflink)"
  # Find the host interface whose ifindex matches that iflink.
  for veth in /sys/class/net/veth*; do
    [[ -e "${veth}/ifindex" ]] || continue
    if [[ "$(cat "${veth}/ifindex")" == "${iflink}" ]]; then
      basename "${veth}"
      return 0
    fi
  done
  die "could not resolve host veth for ${container}"
}

setup() {
  require_root
  resolve_bridge

  log "putting bridge ${BRIDGE} into promiscuous mode"
  ip link set "${BRIDGE}" promisc on

  local target_veth snort_veth suricata_veth
  target_veth="$(host_veth_for "${TARGET_CONTAINER}")"
  snort_veth="$(host_veth_for "${SNORT_CONTAINER}")"
  suricata_veth="$(host_veth_for "${SURICATA_CONTAINER}")"

  log "target   veth : ${target_veth}"
  log "snort    veth : ${snort_veth}"
  log "suricata veth : ${suricata_veth}"

  # Ensure the sniffing engine interfaces are promiscuous too.
  ip link set "${snort_veth}" promisc on
  ip link set "${suricata_veth}" promisc on

  # -------------------------------------------------------------------------
  # Ingress mirroring: everything arriving on the target's host veth gets
  # copied to both engine veths. We attach an ingress qdisc on the target
  # veth, then two mirred filters (one per engine) matching all traffic.
  # -------------------------------------------------------------------------
  log "installing ingress qdisc on ${target_veth}"
  tc qdisc add dev "${target_veth}" handle ffff: ingress

  log "mirroring INGRESS ${target_veth} -> ${snort_veth}"
  tc filter add dev "${target_veth}" parent ffff: protocol all prio 1 u32 \
    match u32 0 0 \
    action mirred egress mirror dev "${snort_veth}"

  log "mirroring INGRESS ${target_veth} -> ${suricata_veth}"
  tc filter add dev "${target_veth}" parent ffff: protocol all prio 2 u32 \
    match u32 0 0 \
    action mirred egress mirror dev "${suricata_veth}"

  # -------------------------------------------------------------------------
  # Egress mirroring: replies FROM the target also need to be seen by the
  # engines (stateful rules track both directions). Mirror the target veth
  # egress via a clsact/handle 1: root qdisc.
  # -------------------------------------------------------------------------
  log "installing clsact qdisc on ${target_veth} for egress mirroring"
  tc qdisc add dev "${target_veth}" clsact

  tc filter add dev "${target_veth}" egress protocol all prio 1 u32 \
    match u32 0 0 \
    action mirred egress mirror dev "${snort_veth}"
  tc filter add dev "${target_veth}" egress protocol all prio 2 u32 \
    match u32 0 0 \
    action mirred egress mirror dev "${suricata_veth}"

  log "mirror active: 100% of target traffic duplicated to both engines"
}

teardown() {
  require_root
  resolve_bridge
  local target_veth
  target_veth="$(host_veth_for "${TARGET_CONTAINER}")"
  log "removing qdiscs from ${target_veth}"
  tc qdisc del dev "${target_veth}" ingress 2>/dev/null || true
  tc qdisc del dev "${target_veth}" clsact 2>/dev/null || true
  ip link set "${BRIDGE}" promisc off 2>/dev/null || true
  log "mirror torn down"
}

case "${1:-setup}" in
  setup)     setup ;;
  --teardown|teardown) teardown ;;
  *) die "usage: $0 [setup|--teardown]" ;;
esac
