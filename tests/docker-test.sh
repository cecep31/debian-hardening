#!/usr/bin/env bash
# Runs the playbook twice inside a throwaway Debian 13 container and checks that:
#   1. it completes without errors,
#   2. the second run changes nothing (idempotent),
#   3. the resulting sshd and nftables configs are valid and hardened,
#   4. an invalid sshd config is rolled back,
#   5. OpenSCAP scores the result against CIS Debian 13 Level 1 Server, every rule counted:
#      nothing is excluded from the scan. Set OSCAP_MIN_PASS to enforce a minimum.
# The playbook runs as PLATFORM (default aws) to exercise the cloud settings.
# Containers have no systemd and share the host kernel, so services are not started and
# a few results read the host's values. Use the score to spot regressions; the score of
# record is a scan of a real server (see README).
set -euo pipefail

IMAGE="${IMAGE:-debian:13}"
PLATFORM="${PLATFORM:-aws}"   # aws | gcp | generic
OSCAP_PROFILE="${OSCAP_PROFILE:-xccdf_org.ssgproject.content_profile_cis_level1_server}"
OSCAP_MIN_PASS="${OSCAP_MIN_PASS:-0}"   # minimum % of applicable rules that pass
OSCAP_TIMEOUT="${OSCAP_TIMEOUT:-60m}"
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${TESTS_DIR}/.." && pwd)"
ANSIBLE_VERSION="$(grep '^ansible==' "${PROJECT_DIR}/requirements.txt" | cut -d= -f3)"

SCAP_DS="$("${TESTS_DIR}/fetch-scap-content.sh")"
REPORT_DIR="${TESTS_DIR}/.cache/reports"
mkdir -p "${REPORT_DIR}"

# The scan walks every file it can see, including bind mounts, so the container gets a lean
# copy of the project (no .venv, .git or caches) instead of the whole directory.
SRC_COPY="$(mktemp -d)"
trap 'rm -rf "${SRC_COPY}"' EXIT
tar -C "${PROJECT_DIR}" --exclude=./.venv --exclude=./.git --exclude=./tests/.cache --exclude=./.ansible -cf - . \
  | tar -C "${SRC_COPY}" -xf -

# NET_ADMIN only affects the container's own network namespace; needed for `nft -c`.
docker run --rm -i --cap-add NET_ADMIN \
  -v "${SRC_COPY}:/src:ro" \
  -v "${SCAP_DS}:/scap/ds.xml:ro" \
  -v "${REPORT_DIR}:/reports" \
  -e ANSIBLE_VERSION="${ANSIBLE_VERSION}" \
  -e OSCAP_PROFILE="${OSCAP_PROFILE}" \
  -e PLATFORM="${PLATFORM}" \
  -e OSCAP_MIN_PASS="${OSCAP_MIN_PASS}" \
  -e OSCAP_TIMEOUT="${OSCAP_TIMEOUT}" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
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

# Bind-mounted files belong to the host user; without a matching account the scan would
# count them as "unowned files", which is an artifact of the test, not of the server.
getent group "${HOST_GID}" >/dev/null || groupadd -g "${HOST_GID}" hostgroup
getent passwd "${HOST_UID}" >/dev/null || useradd -u "${HOST_UID}" -g "${HOST_GID}" -M -s /usr/sbin/nologin hostuser

# Mimic a cloud image that sets SSH options in the main config (DigitalOcean ships
# "PermitRootLogin yes" there); the role must comment these out.
apt-get install -y -qq openssh-server >/dev/null
printf 'PermitRootLogin yes\nX11Forwarding yes\nClientAliveInterval 120\n' >> /etc/ssh/sshd_config

run() {
  ansible-playbook site.yml -i localhost, -c local \
    -e '{"hardening_firewall_allowed_tcp_ports": [80, 443]}' \
    -e hardening_platform="${PLATFORM}" "$@"
}

echo "==> first run (platform: ${PLATFORM})"
run | tee /tmp/first.log
grep -q "Platform: ${PLATFORM}" /tmp/first.log || { echo "FAIL: platform not applied"; exit 1; }

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
! grep -q 'flush ruleset' /etc/nftables.conf      || { echo "FAIL: ruleset flush would wipe fail2ban"; exit 1; }
grep -q 'update @ssh_meter_v4' /etc/nftables.conf || { echo "FAIL: per-source SSH limit"; exit 1; }
grep -q 'kernel.kptr_restrict = 1' /etc/sysctl.d/60-hardening.conf || { echo "FAIL: sysctl"; exit 1; }
grep -q 'install cramfs /bin/false' /etc/modprobe.d/hardening.conf || { echo "FAIL: modprobe"; exit 1; }
grep -q 'backend = systemd' /etc/fail2ban/jail.d/sshd.local || { echo "FAIL: fail2ban"; exit 1; }
grep -qE '^UMASK\s+027' /etc/login.defs           || { echo "FAIL: umask"; exit 1; }
test -f /etc/logrotate.d/sudo-hardening           || { echo "FAIL: sudo log rotation"; exit 1; }
grep -q 'install usb-storage /bin/false' /etc/modprobe.d/hardening.conf || { echo "FAIL: usb-storage"; exit 1; }
case "${PLATFORM}" in
  aws|gcp)
    grep -qx 'net.ipv6.conf.all.accept_ra = 1' /etc/sysctl.d/60-hardening.conf || { echo "FAIL: accept_ra must stay on in cloud"; exit 1; }
    grep -q '^NTP=' /etc/systemd/timesyncd.conf.d/10-hardening.conf || { echo "FAIL: cloud NTP"; exit 1; } ;;
  *)
    grep -qx 'net.ipv6.conf.all.accept_ra = 0' /etc/sysctl.d/60-hardening.conf || { echo "FAIL: accept_ra"; exit 1; } ;;
esac
! dpkg -s telnet >/dev/null 2>&1                   || { echo "FAIL: telnet still installed"; exit 1; }

echo "==> invalid sshd config must be rolled back"
cp /etc/ssh/sshd_config.d/10-hardening.conf /tmp/sshd-good.conf
if ansible-playbook site.yml -i localhost, -c local --tags ssh \
     -e '{"hardening_firewall_allowed_tcp_ports": [80, 443], "hardening_ssh_max_auth_tries": "bogus"}' \
     -e hardening_platform="${PLATFORM}" \
     >/tmp/badssh.log 2>&1; then
  echo "FAIL: invalid sshd config was accepted"; exit 1
fi
grep -q 'previous sshd config was kept' /tmp/badssh.log || { echo "FAIL: no rollback message"; cat /tmp/badssh.log; exit 1; }
cmp -s /tmp/sshd-good.conf /etc/ssh/sshd_config.d/10-hardening.conf || { echo "FAIL: sshd config not restored"; exit 1; }
sshd -t                                           || { echo "FAIL: sshd config broken after rollback"; exit 1; }

echo "==> cloud image conflicts and CIS settings"
grep -Eq '^# PermitRootLogin yes  # set in' /etc/ssh/sshd_config || { echo "FAIL: main sshd_config conflict not commented"; exit 1; }
grep -q '^# BEGIN ANSIBLE MANAGED: hardening sshd' /etc/ssh/sshd_config || { echo "FAIL: role block missing in sshd_config"; exit 1; }
# Outside the role's own block (scanners read only this file), no managed directive may remain.
! sed '/^# BEGIN ANSIBLE MANAGED: hardening sshd/,/^# END ANSIBLE MANAGED: hardening sshd/d' /etc/ssh/sshd_config \
    | grep -Eiq '^\s*(PermitRootLogin|X11Forwarding|ClientAliveInterval)\s' || { echo "FAIL: conflicting sshd directive left"; exit 1; }
[ "$(stat -c %a /etc/ssh/sshd_config)" = 600 ] || { echo "FAIL: sshd_config mode"; exit 1; }
sshd -T > /tmp/sshd.txt
grep -qx 'permitrootlogin no' /tmp/sshd.txt        || { echo "FAIL: root login after cleanup"; exit 1; }
grep -qx 'banner /etc/issue.net' /tmp/sshd.txt     || { echo "FAIL: ssh banner"; exit 1; }
! grep -q nullok /etc/pam.d/common-auth            || { echo "FAIL: nullok still in common-auth"; exit 1; }
grep -Eq 'pam_pwhistory.so .*remember=24' /etc/pam.d/common-password || { echo "FAIL: pwhistory"; exit 1; }
grep -q 'pam_pwquality.so' /etc/pam.d/common-password || { echo "FAIL: pwquality not in PAM"; exit 1; }
grep -qE '^minlen = 14' /etc/security/pwquality.conf || { echo "FAIL: pwquality minlen"; exit 1; }
grep -q 'noexec' /etc/fstab                        || { echo "FAIL: /dev/shm noexec"; exit 1; }
[ "$(stat -c %a /etc/crontab)" = 600 ]             || { echo "FAIL: crontab mode"; exit 1; }
grep -q '^Storage=persistent' /etc/systemd/journald.conf || { echo "FAIL: journald"; exit 1; }
grep -q 'pam_faillock.so authfail' /etc/pam.d/common-auth || { echo "FAIL: faillock not in common-auth"; exit 1; }
grep -q 'pam_faillock.so' /etc/pam.d/common-account || { echo "FAIL: faillock not in common-account"; exit 1; }
grep -qE '^deny = 4' /etc/security/faillock.conf || { echo "FAIL: faillock deny"; exit 1; }
test -s /var/lib/aide/aide.db                      || { echo "FAIL: AIDE database missing"; exit 1; }
test -f /etc/systemd/system/aidecheck.timer        || { echo "FAIL: aidecheck.timer missing"; exit 1; }
[ "$(grep -rhcE '^\s*(AllowUsers|AllowGroups)\s' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ | paste -sd+ | bc 2>/dev/null || echo 0)" -le 1 ] || { echo "FAIL: more than one SSH allow list entry"; exit 1; }
grep -q '^FallbackNTP=0.debian.pool.ntp.org' /etc/systemd/timesyncd.conf.d/10-hardening.conf || { echo "FAIL: FallbackNTP"; exit 1; }
grep -Eq 'noexec' <(grep -E '[[:space:]]/tmp[[:space:]]' /etc/fstab) || { echo "FAIL: /tmp noexec"; exit 1; }

echo "==> OpenSCAP: ${OSCAP_PROFILE}"
apt-get install -y -qq --no-install-recommends openscap-scanner >/dev/null
# Make OpenSCAP treat the container like a VM: it skips most rules when /.dockerenv
# exists or linux-base is missing. Rules about the running kernel then read the
# host's values, so a few results here depend on the machine running the test.
rm -f /.dockerenv /run/.containerenv
apt-get install -y -qq --no-install-recommends linux-base >/dev/null
# Exit code 2 means "some rules failed", which is expected; anything else is an error.
rc=0
timeout "${OSCAP_TIMEOUT}" oscap xccdf eval --profile "${OSCAP_PROFILE}" \
  --results /reports/oscap-results.xml --report /reports/oscap-report.html \
  /scap/ds.xml > /tmp/oscap.txt 2>/tmp/oscap.err || rc=$?
chown "${HOST_UID}:${HOST_GID}" /reports/oscap-results.xml /reports/oscap-report.html 2>/dev/null || true
[ "${rc}" -ne 124 ] || { echo "FAIL: oscap took longer than ${OSCAP_TIMEOUT}"; tail -3 /tmp/oscap.txt; exit 1; }
[ "${rc}" -eq 0 ] || [ "${rc}" -eq 2 ] || { echo "FAIL: oscap exited ${rc}"; cat /tmp/oscap.err; exit 1; }

PASS="$(grep -cE '^Result\s+pass$' /tmp/oscap.txt || true)"
FAIL="$(grep -cE '^Result\s+fail$' /tmp/oscap.txt || true)"
NA="$(grep -cE '^Result\s+notapplicable$' /tmp/oscap.txt || true)"
OTHER="$(grep -E '^Result\s' /tmp/oscap.txt | grep -cvE '\s(pass|fail|notapplicable)$' || true)"
SCORE="$(grep -oE '<score system="urn:xccdf:scoring:default"[^>]*>[0-9.]+' /reports/oscap-results.xml | sed 's/.*>//')"
PASS_PCT=$(( PASS * 100 / (PASS + FAIL > 0 ? PASS + FAIL : 1) ))

echo "Rules: ${PASS} pass, ${FAIL} fail, ${NA} not applicable, ${OTHER} other"
echo "Pass rate (applicable rules): ${PASS_PCT}%"
echo "XCCDF default score: ${SCORE}/100"
echo "Failed rules:"
awk -F'\t' '/^Title/ {t=$2} /^Result/ && $2=="fail" {print "  - " t}' /tmp/oscap.txt
echo "HTML report: tests/.cache/reports/oscap-report.html"

if [ "${PASS_PCT}" -lt "${OSCAP_MIN_PASS}" ]; then
  echo "FAIL: pass rate ${PASS_PCT}% is below ${OSCAP_MIN_PASS}%"; exit 1
fi

echo "==> all checks passed"
SCRIPT
