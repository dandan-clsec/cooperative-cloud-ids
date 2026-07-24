# Vulnerable target surface: DVWA (web) + OpenSSH (brute-force surface).
# Based on the well-known vulnerables/web-dvwa image, with an SSH daemon
# added so Hydra has an authentication endpoint to attack.
FROM vulnerables/web-dvwa:latest

ENV DEBIAN_FRONTEND=noninteractive

# The base image ships Debian Stretch, which is EOL and removed from the
# regular mirrors — repoint apt at archive.debian.org before installing.
RUN sed -i \
      -e 's|deb.debian.org|archive.debian.org|g' \
      -e 's|security.debian.org|archive.debian.org|g' \
      -e '/stretch\/updates/d' \
      -e '/stretch-updates/d' \
      /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid-until

# Debian moved Stretch's archive-signing keys off the live keyserver network,
# so pull the actual (expired but still valid-for-verification) keys directly
# from Debian's keyring package archive rather than skipping auth entirely.
RUN apt-get update -o Acquire::AllowInsecureRepositories=true \
      -o APT::Get::AllowUnauthenticated=true && \
    apt-get install -y --allow-unauthenticated debian-archive-keyring && \
    apt-get update

# Install and configure an SSH daemon with a weak, well-known credential
# (root:password) purely so brute-force detection can be exercised in the lab.
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server iproute2 && \
    mkdir -p /var/run/sshd && \
    echo 'root:password' | chpasswd && \
    sed -i 's/#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/target-entrypoint.sh
RUN chmod +x /usr/local/bin/target-entrypoint.sh

EXPOSE 80 22

ENTRYPOINT ["/usr/local/bin/target-entrypoint.sh"]
