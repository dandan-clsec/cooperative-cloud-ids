# Cooperative Cloud IDS Framework (Snort 3 + Suricata 7)

A single-node, reproducible implementation of the cooperative intrusion
detection framework described in *"A Cooperative Implementation of Cloud IDS
Framework: Evaluating Snort vs Suricata"*. It runs Snort 3 and Suricata 7
side-by-side against **one kernel-mirrored traffic stream** (no packet
duplication contention, no competitive race), over a LocalStack-emulated cloud
plane, and scores detection with an **OR-merge** accuracy model.

> **Lab use only.** Everything targets a deliberately vulnerable container on
> an isolated bridge network. Do not point the attack tooling at any system you
> do not own.

> **On Windows?** See [WINDOWS_SETUP.md](WINDOWS_SETUP.md) — this project needs
> real Linux kernel networking (`tc`, `tcpdump`, `nsenter`), so it runs under
> WSL2, not native PowerShell/cmd.

## Architecture

```
[VM2 Kali Attacker] --attack--> [ ids_net 172.20.0.0/16 bridge ]
                                        |
                     tc mirred (100% copy, both directions)
                        /               |               \
             [DVWA + SSH target]   [Snort 3]        [Suricata 7]
             172.20.0.20          172.20.0.30       172.20.0.31
                                        \               /
                                     logs/snort     logs/suricata
                                            \         /
                            [Node Exporter] -> [Prometheus] (5s) -> Grafana
                                            \         /
                            orchestrator.py  ->  validator.py (OR-merge)
```

| Component            | Version   | Role                                        |
|----------------------|-----------|---------------------------------------------|
| LocalStack           | 2.3.0     | AWS emulation (EC2, S3, VPC)                 |
| DVWA + SSH           | 1.10      | Vulnerable target surface                   |
| Snort 3              | 3.1       | Single-threaded signature engine (passive)  |
| Suricata             | 7.0.3     | Multi-threaded protocol-aware engine        |
| Prometheus / Node Exporter | 2.48.0 / 1.6.1 | Telemetry (5s scrape)             |

## File layout

```
cooperative-ids/
├── docker-compose.yml         # one-command environment
├── prometheus/prometheus.yml  # 5s scrape config
├── snort/{Dockerfile,snort.lua}
├── suricata/suricata.yaml
├── target/{Dockerfile,entrypoint.sh}   # DVWA + SSH
├── rules/local.rules          # DoS / SQLi / brute-force signatures
├── scripts/
│   ├── mirror_setup.sh        # tc mirred kernel mirror (run on host)
│   ├── orchestrator.py        # trial driver + telemetry bundle
│   ├── validator.py           # OR-merge accuracy scoring
│   ├── attack.sh              # hping3 / sqlmap / hydra launcher (Kali)
│   ├── run_experiment.sh      # full sweep
│   ├── fetch_rules.sh         # optional full ET Open ruleset
│   └── ground_truth.json      # injected attack metadata
└── logs/ , results/           # engine alerts + per-trial telemetry
```

## Quick start

```bash
# 1. Bring up the whole environment
cd cooperative-ids
docker compose up -d

# 2. Install the kernel traffic mirror on the HOST (needs root; not a container)
sudo ./scripts/mirror_setup.sh

# 3. Run a single cooperative trial (from this VM)
python3 scripts/orchestrator.py --condition cooperative --attack dos --duration 120
#    ... when prompted, launch the attack from the Kali node:
#    ./scripts/attack.sh dos 172.20.0.20

# 4. Score the trial with the OR-merge model
python3 scripts/validator.py --condition cooperative \
    --results-dir results/cooperative_dos_<timestamp>

# 5. Or run the entire sweep (4 conditions x 3 attacks x 3 trials)
TRIALS=3 ./scripts/run_experiment.sh
```

## Web GUI (control panel)

A Flask dashboard wraps the whole framework so you can drive it from a browser
instead of the CLI — service status, one-click trials, live telemetry, and
OR-merge accuracy results.

```bash
pip install -r gui/requirements.txt
python3 gui/dashboard.py
# open http://localhost:5000
```

From the dashboard you can:
- **Stack Up / Down** — runs `docker compose up -d` / `down`
- **Install Mirror** — runs `sudo scripts/mirror_setup.sh` on the host
- **Launch Trial** — pick condition + attack + window; it calls
  `orchestrator.py`, shows the exact attacker command to run, streams the job
  console, then auto-runs `validator.py` when the trial finishes
- **Results History** — every trial's CPU %, memory, packet loss, and
  TP/FP/FN + accuracy, colour-coded; re-score any trial on demand
- **Live Telemetry** — CPU and memory pulled from Prometheus every few seconds

The dashboard shells out to the existing scripts, so CLI and GUI share one
source of truth for trial logic.

Grafana is not bundled but Prometheus is exposed on `http://localhost:9090`;
point a Grafana instance at it (add `prom/... ` if you want the dashboards).
The DVWA surface is on `http://localhost:8090`, SSH on `localhost:2222`.

## Conditions

`baseline` (no engines), `snort_only`, `suricata_only`, `cooperative`. The
orchestrator starts/stops the relevant engine containers per condition while the
mirror keeps feeding both veths.

## OR-merge scoring

`validator.py` counts an injected attack event as **detected (TP)** if *either*
Snort *or* Suricata raised a matching alert; **FN** if neither did; and **FP**
for any alert not attributable to an injected event.

```
Accuracy = TP / (TP + FP + FN) * 100
```

## Notes / limitations

- The mirror script resolves the docker bridge + container veths automatically
  via `docker inspect` + `nsenter`; it must run on the host that owns the
  bridge, not inside a container.
- LocalStack 2.3.0 covers VPC primitives through its EC2 provider.
- Detection accuracy depends on ruleset freshness — run `scripts/fetch_rules.sh`
  to pull the full Emerging Threats Open ruleset.
```


GITHUB REPOSITORY LINK: https://github.com/dandan-clsec/cooperative-cloud-ids
