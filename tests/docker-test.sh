#!/usr/bin/env bash
# Runs the playbook twice inside a throwaway Debian 13 container and checks that:
#   1. it completes without errors,
#   2. the second run changes nothing (idempotent),
#   3. the resulting sshd and nftables configs are valid and hardened.
# Containers have no systemd, so services are configured but not started.
set -euo pipefail

IMAGE="${IMAGE:-debian:13}"
ANSIBLE_VERSION="$(grep '^ansible==' "$(dirname "$0")/../requirements.txt" | cut -d= -f3)"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# NET_ADMIN only affects the container's own network namespace; needed for `nft -c`.
docker run --rm -i --cap-add NET_ADMIN \
  -v "${PROJECT_DIR}:/src:ro" \
  -e ANSIBLE_VERSION="${ANSIBLE_VERSION}" \
  "${IMAGE}" bash -s <<'SCRIPT'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "==> installing ansible ${ANSIBLE_VERSION}"
apt-get update -qq
apt-get install -y -qq python3 python3-venv >/dev/null
python3 -m venv /opt/ansible
/opt/ansible/bin/pip install -q "ansible==${ANSIBLE_VERSION}"
export PATH="/opt/ansible/bin:${PATH}"

cp -r /src /work && cd /work
mkdir -p /run/sshd  # normally created by ssh.service

run() {
  ansible-playbook site.yml -i localhost, -c local \
    -e '{"hardening_firewall_allowed_tcp_ports": [80, 443]}' "$@"
}

echo "==> first run"
run

echo "==> invalid port input must be rejected"
if ansible-playbook site.yml -i localhost, -c local \
     -e hardening_firewall_allowed_tcp_ports='[80,443]' >/tmp/bad.log 2>&1; then
  echo "FAIL: string port list was accepted"; exit 1
fi
grep -q 'must be lists of port numbers' /tmp/bad.log || { echo "FAIL: wrong error"; cat /tmp/bad.log; exit 1; }

echo "==> second run (must change nothing)"
run | tee /tmp/second.log
grep -Eq 'changed=0 .*failed=0' /tmp/second.log || { echo "FAIL: not idempotent"; exit 1; }

echo "==> checking results"
sshd -T > /tmp/sshd.txt  # saved first: grep -q on a pipe can SIGPIPE sshd under pipefail
grep -qx 'permitrootlogin no' /tmp/sshd.txt        || { echo "FAIL: root login"; exit 1; }
grep -qx 'passwordauthentication no' /tmp/sshd.txt || { echo "FAIL: password auth"; exit 1; }
grep -qx 'x11forwarding no' /tmp/sshd.txt          || { echo "FAIL: X11"; exit 1; }
nft -c -f /etc/nftables.conf                      || { echo "FAIL: nftables syntax"; exit 1; }
fail2ban-client -t >/dev/null                      || { echo "FAIL: fail2ban config"; exit 1; }
grep -q 'policy drop' /etc/nftables.conf          || { echo "FAIL: firewall policy"; exit 1; }
grep -q 'tcp dport { 80, 443 } accept' /etc/nftables.conf || { echo "FAIL: allowed ports"; exit 1; }
grep -q 'kernel.kptr_restrict = 2' /etc/sysctl.d/60-hardening.conf || { echo "FAIL: sysctl"; exit 1; }
grep -q 'install cramfs /bin/false' /etc/modprobe.d/hardening.conf || { echo "FAIL: modprobe"; exit 1; }
grep -q 'backend = systemd' /etc/fail2ban/jail.d/sshd.local || { echo "FAIL: fail2ban"; exit 1; }
grep -qE '^UMASK\s+027' /etc/login.defs           || { echo "FAIL: umask"; exit 1; }
! dpkg -s telnet >/dev/null 2>&1                   || { echo "FAIL: telnet still installed"; exit 1; }

echo "==> all checks passed"
SCRIPT
