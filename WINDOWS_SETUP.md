# Running on Windows (via WSL2)

This project relies on real Linux kernel networking — `tc mirred` traffic
mirroring, `tcpdump` packet capture, and `nsenter` into container network
namespaces. None of that exists on native Windows, and Docker Desktop's
containers run inside a hidden Linux VM anyway. The supported path is
**WSL2** (Windows Subsystem for Linux): a real Linux kernel running under
Windows, with Docker Desktop's WSL2 backend sharing its networking into your
WSL distro. Everything in this repo — bash scripts, `tc`, `tcpdump` — then
runs completely unmodified.

Do all of the steps below **inside a WSL2 Ubuntu terminal**, not PowerShell
or cmd.exe. The GUI is still reached from a normal Windows browser.

## 1. Install WSL2 + Ubuntu

In an elevated PowerShell:

```powershell
wsl --install -d Ubuntu
```

Reboot if prompted, then open "Ubuntu" from the Start menu and finish the
first-run setup (create a Linux username/password). Confirm you're on WSL2:

```powershell
wsl -l -v
# Ubuntu should show VERSION 2
```

## 2. Install Docker Desktop for Windows

Install Docker Desktop, then in **Settings**:

- **General**: enable "Use the WSL 2 based engine".
- **Resources → WSL Integration**: enable integration for the "Ubuntu"
  distro.
- **Resources → Advanced**: give it at least 4 CPUs / 6 GB RAM — the Snort 3
  image compiles from source and the full stack is 6 containers.

Verify from inside the Ubuntu WSL terminal (not PowerShell):

```bash
docker version      # should show both Client and Server
docker compose version
```

If `docker` isn't found here, the WSL integration checkbox above wasn't
applied — recheck it and restart Docker Desktop.

## 3. Get the project into the Linux filesystem

Don't work out of `/mnt/c/...` (that's the Windows filesystem through a
9P/DrvFs mount — slow, and permission bits/symlinks/`nsenter` don't behave
like a real Linux filesystem there). Copy or clone the project into your WSL
home directory instead:

```bash
cd ~
# e.g. if it arrived as a zip in Windows Downloads:
cp -r /mnt/c/Users/<you>/Downloads/cooperative-ids ~/cooperative-ids
cd ~/cooperative-ids
```

## 4. Bring up the stack

```bash
docker compose up -d
docker compose ps        # all 6 containers should be Up
```

The Snort 3 image builds from source on first run (compiles libdaq +
Snort), so the first `up` takes several minutes.

- DVWA: `http://localhost:8090` (from Windows or WSL — WSL2 forwards
  `localhost` both ways automatically)
- Prometheus: `http://localhost:9090`
- SSH into target: `ssh root@localhost -p 2222` (password `password`)

## 5. Packet capture permissions

`orchestrator.py` runs `tcpdump` directly (no sudo), so it needs the capture
capability granted once:

```bash
sudo apt update && sudo apt install -y tcpdump
sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)
```

Without this, launching a trial fails with "You don't have permission to
capture on that device."

## 6. Install the kernel traffic mirror

```bash
sudo ./scripts/mirror_setup.sh
```

This resolves the `ids_net` bridge and each container's host-side veth via
`docker inspect` + `nsenter`, which works here because Docker Desktop's WSL2
integration shares its network namespace into the Ubuntu distro — the same
`br-...`/`veth...` interfaces `docker network inspect` reports are visible
to this shell.

## 7. Run the dashboard

```bash
python3 -m venv .venv && source .venv/bin/activate   # optional but tidy
pip install -r gui/requirements.txt
python3 gui/dashboard.py
```

Open `http://localhost:5000` from a normal Windows browser.

## 8. Optional: passwordless mirror install from the GUI

The dashboard's "Install Mirror" button runs `sudo scripts/mirror_setup.sh`
as a background subprocess with no terminal attached, so if `sudo` prompts
for a password there it will just hang. Either run step 6 manually from the
terminal instead of clicking the button, or scope a NOPASSWD rule to that
one script:

```bash
echo "$(whoami) ALL=(root) NOPASSWD: $(realpath scripts/mirror_setup.sh)" | \
  sudo tee /etc/sudoers.d/coop-ids-mirror
sudo chmod 440 /etc/sudoers.d/coop-ids-mirror
```

## Gotchas specific to Windows/WSL2

- **Line endings**: if any `.sh` file gets re-saved from a native Windows
  editor with CRLF line endings, bash will fail with `$'\r': command not
  found`. Edit inside WSL (or VS Code's Remote-WSL extension), or run
  `dos2unix scripts/*.sh` if in doubt.
- **Firewall prompts**: Windows Defender may prompt to allow Docker/WSL
  networking on first run — allow it, or container-to-container traffic and
  the mirror won't work.
- **The Kali attacker (VM2)** is unchanged by any of this — it's a separate
  machine that reaches the target over `ids_net`'s IP range
  (`172.20.0.0/16`) or the Windows host's LAN IP + published ports,
  exactly as it would against a Linux host.
- **WSL2 shutdown**: if the WSL VM restarts (Windows update, `wsl --shutdown`,
  laptop sleep), the mirror (step 6) and any running trial are lost —
  re-run `mirror_setup.sh` after the containers come back up.
