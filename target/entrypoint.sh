#!/bin/bash
# Start SSH daemon in the background, then hand off to the DVWA entrypoint so
# both the web surface and the SSH surface are live in a single container.
set -e

# Generate host keys on first boot if missing.
ssh-keygen -A 2>/dev/null || true
service ssh start || /usr/sbin/sshd

# Launch the original DVWA/Apache+MySQL entrypoint (foreground).
exec /main.sh
