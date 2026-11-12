# Debian Hardening — Template (Ansible)

A small starter template that applies baseline security hardening to
**Debian 13 (trixie)** servers over SSH, with **public cloud instances (AWS EC2,
GCP Compute Engine)** as the main target.
It is meant as a **first init** for new servers: sensible defaults, one role,
easy to read and extend.

> **Status:** template. It has only been tested in a throwaway Debian 13 container,
> never against a real server. Run `make plan` and read the diff before applying.

Based on selected controls from the **CIS Debian Linux Benchmark**, not a full implementation.

## What it does

| Area | Changes | Tag |
|---|---|---|
| SSH | No root login, keys only, no X11/agent/TCP forwarding, CIS values (auth tries, MaxStartups, timeouts), strong ciphers/KEX/MACs, login banner; conflicting lines left by cloud images are commented out | `ssh` |
| Firewall | nftables: drop all inbound except SSH (rate limited per source IP) and the ports you allow | `firewall` |
| Updates | `unattended-upgrades` for security patches (reboot off by default) | `updates` |
| Kernel | Network and kernel sysctl hardening (no IP forwarding), re-applied after the network is up; conflicting vendor sysctl lines commented out; block rarely used modules, USB storage and firewire | `kernel` |
| Brute force | fail2ban for SSH, using the systemd journal and nftables | `fail2ban` |
| Audit | auditd rules for identity files, sudo, SSH config, time, kernel modules | `auditd` |
| System | AppArmor and time sync on, core dumps off, umask 027 (login, profile, bashrc), password ageing and quality (`pam_pwquality`), `su` limited to a group, sudo logging, strict permissions on log and shadow backup files | `system` |
| Accounts | Login banners, idle shell logout (`TMOUT` 900 s), lock accounts 45 days after password expiry, no login shell for system accounts, private dotfiles | `accounts` |
| Passwords | `pam_pwquality` (14 chars, 4 classes, root too), password history (24), no empty passwords (`nullok` removed) via pam-auth-update profiles | `pam` |
| Cron | `crontab` and `cron.*` root-only, `cron.allow` / `at.allow` | `cron` |
| Logging | journald persistent and compressed; rsyslog installed and fed by journald (no network listener); `systemd-journal-remote` package present with its receiver off | `logging` |
| Mounts | `/dev/shm` with `nodev,nosuid,noexec` | `mounts` |
| Boot | AppArmor on the kernel command line, `grub.cfg` root-only | `boot` |
| Cleanup | Remove telnet, rsh, talk, nis | `packages` |

**Strict controls** (on by default so the compliance scan passes; each can disrupt some
workloads, and switching one off makes the matching CIS rule fail):

| Variable | What it does | Watch out for |
|---|---|---|
| `hardening_faillock_enabled` | Lock an account for 15 min after 4 failed passwords | Mistyped sudo or `su` passwords lock the account (key-only SSH is unaffected) |
| `hardening_tmp_noexec` | Mount `/tmp` with `noexec` | Installers and build tools that run scripts from `/tmp` fail |
| `hardening_aide_enabled` | AIDE file integrity database and daily check | First build reads the whole disk; daily I/O |
| `hardening_ssh_restrict_access` | Only the user Ansible connects as may log in over SSH, unless you set `hardening_ssh_allow_users` or `_groups` | Other users cannot log in until you list them |

## Public cloud (AWS / GCP)

The role detects the platform from DMI facts (`hardening_platform: auto`) and prints it
at the start of the run. Set `hardening_platform: aws`, `gcp` or `generic` to override.

| Setting | AWS / GCP | Elsewhere (`generic`) |
|---|---|---|
| Time source (systemd-timesyncd) | AWS: `169.254.169.123` (Amazon Time Sync); GCP: `metadata.google.internal` | Debian defaults |
| IPv6 router advertisements (`accept_ra`) | **on**: the IPv6 default route comes from them | off (CIS) |
| SSH allow list on GCP | warns: OS Login and guest-agent users other than the Ansible user are blocked unless listed | — |

Keep the cloud firewall (Security Groups, VPC firewall rules) as the first layer; the
nftables rules here are a second layer. Open the same ports in both.

**AWS:** Debian images use the `admin` user, which is the default `ansible_user` in
`inventory/hosts.example.yml`. EC2 Instance Connect keeps working (it uses
`AuthorizedKeysCommand`, not passwords).

**GCP:** SSH is limited to the user Ansible connects as. `gcloud compute ssh` and OS Login
create other users on first login, and they are blocked until you list them in
`hardening_ssh_allow_users` or put them in a group listed in `hardening_ssh_allow_groups`.
**AWS:** the same applies to any user besides `admin`.

## Lockout protection

Before changing anything, the role stops if:

- the host is not Debian 13,
- you connect as `root` while root login is being disabled,
- your user has no `~/.ssh/authorized_keys` while password login is being disabled,
- your user is missing from `hardening_ssh_allow_users`,
- the firewall port lists are not lists of valid port numbers.

SSH stays allowed in the firewall on `hardening_ssh_port`. The new sshd config is
validated with `sshd -t` before SSH is reloaded; if it is invalid, the previous file
is put back so a reboot cannot leave sshd broken.

## Layout

```
.
├── site.yml                   # playbook
├── inventory/
│   ├── hosts.example.yml      # copy to hosts.yml
│   └── group_vars/all.yml     # your settings
├── roles/hardening/
│   ├── defaults/main.yml      # every option with its default
│   ├── tasks/                 # one file per area
│   ├── templates/             # config files written to the server
│   └── handlers/main.yml
├── tests/docker-test.sh       # container test
└── Makefile
```

## Usage

### 1. Prepare the server

Each server needs a **non-root user with sudo and your SSH key** installed.
Log in once as that user to confirm it works.

### 2. Set up locally

```bash
make setup                                          # installs Ansible into .venv
cp inventory/hosts.example.yml inventory/hosts.yml  # add your servers
```

Edit `inventory/group_vars/all.yml`:

| Variable | Purpose |
|---|---|
| `hardening_platform` | `auto` (detects AWS/GCP), `aws`, `gcp` or `generic` |
| `hardening_ssh_port` | SSH port (stays open in the firewall) |
| `hardening_ssh_allow_users` | Users allowed to log in over SSH. Empty means only the user Ansible connects as (see `hardening_ssh_restrict_access`) |
| `hardening_firewall_allowed_tcp_ports` | Extra inbound ports, e.g. `[80, 443]` |
| `hardening_auto_reboot` | Reboot automatically after kernel updates |

Every other option is in `roles/hardening/defaults/main.yml`.

### 3. Dry run, then apply

```bash
make plan  LIMIT=web-01   # shows what would change, changes nothing
make apply LIMIT=web-01   # apply to one server first
make apply                # then to all
```

Run a single area with tags, for example:

```bash
.venv/bin/ansible-playbook site.yml --limit web-01 --tags ssh,firewall --diff
```

**Keep your current SSH session open** until you have confirmed you can open a new one.

## Testing

```bash
make lint   # syntax check + ansible-lint (production profile)
make test   # runs the playbook twice in a throwaway Debian 13 container (needs Docker)
```

The container test checks that the playbook completes, that a second run changes
nothing, that bad port input is rejected, that an invalid sshd config is rolled back,
and that the resulting sshd, nftables and fail2ban configs are valid. Containers have
no systemd, so services are configured but not started there.

The playbook runs as `PLATFORM=aws` by default, so the cloud settings are tested
(`PLATFORM=gcp` or `generic` for the others).

It ends with an **OpenSCAP** scan against **CIS Debian 13 Level 1 Server**. The scan is
never filtered: every rule of the profile counts, there is no tailoring file and no
skipped rule. It prints the pass rate, the XCCDF score and the failing rules, and writes
the full report to `tests/.cache/reports/oscap-report.html`.

Debian's own `ssg-debian` package has no Debian 13 content yet, so
`tests/fetch-scap-content.sh` downloads the upstream
[ComplianceAsCode](https://github.com/ComplianceAsCode/content) release once
(~180 MB, pinned version and SHA-512), keeps only `ssg-debian13-ds.xml` in
`tests/.cache/`, and reuses it on later runs.

Before scanning, the test removes `/.dockerenv` and installs `linux-base` so OpenSCAP
evaluates the container like a VM; otherwise it marks most rules "not applicable".
Rules about the running kernel then read the host's values, and there is no GRUB or
running systemd, so the container result is a regression check, not the score of record.
Options:

```bash
OSCAP_MIN_PASS=90 make test   # fail if under 90% of applicable rules pass
PLATFORM=gcp make test        # test the GCP settings
OSCAP_TIMEOUT=2h make test    # the scan stops after 60 minutes by default
```

### Score of record: scan a real instance

Scan the instance itself after applying. Copy
`tests/.cache/ssg-0.1.82-ssg-debian13-ds.xml` to it, then:

```bash
sudo apt install openscap-scanner
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --report report.html ssg-0.1.82-ssg-debian13-ds.xml
```

### Remediations not applied on purpose

Only the role's remediation may be left out, never the scan. These rules fail in the scan
because the role does not change the setting, for the reason given:

| Rule | Why the role does not remediate it |
|---|---|
| `grub2_password`, `grub2_uefi_password` | Instances boot unattended with no console. A GRUB password needs a secret you must provide, and gets in the way of boot and recovery |
| `sysctl_net_ipv6_conf_{all,default}_accept_ra` (AWS/GCP only) | The IPv6 default route comes from router advertisements; the role sets it to 0 on other platforms, where the rule passes |
| `service_systemd-journal-upload_enabled`, `systemd_journal_upload_url`, `systemd_journal_upload_server_tls` | Need a remote log server and certificates only you can supply; the upload service cannot run without them |
| `journald_disable_forward_to_syslog` | The profile also requires `journald_forward_to_syslog` (the opposite setting), so one of the two always fails. The role installs rsyslog, which makes the three rsyslog rules pass |
| `package_ufw_installed` | The firewall is nftables, with a per-source SSH rate limit that UFW cannot express in the same way |
| `package_chrony_installed` | Time is synchronized by systemd-timesyncd |

## Good to know

- **Changing the SSH port.** Set `ansible_port` in the inventory to the new port in the
  same change, or the next run cannot connect. Keep your current session open.
- **Docker hosts.** The firewall drops forwarded traffic, which breaks Docker networking.
  Leave `hardening_firewall_enabled: false` on Docker hosts or adapt the ruleset.
- **IPv6 router advertisements** are ignored (`accept_ra = 0`) on `generic` hosts and
  kept on for AWS/GCP. Set `hardening_ipv6_accept_ra: true` on other hosts that get
  their IPv6 address through SLAAC.
- **TCP forwarding is off**, so SSH tunnels and port forwarding stop working.
  Set `hardening_ssh_allow_tcp_forwarding: true` if you need them.
- **`su` is limited** to members of `hardening_su_group` (`sugroup`, created empty), so
  `su` stops working for everyone until you add members. `sudo` is unaffected.
  Set `hardening_su_group: ""` to keep `su` open.
- **Kernel modules** are blocked on next load; already loaded modules stay until reboot.
- **IP forwarding is off.** Routers, NAT instances and Docker hosts need
  `hardening_ip_forwarding: true`.
- **Idle shells log out after 15 minutes** (`TMOUT`, read-only). Set
  `hardening_shell_timeout: 0` to turn it off.
- **Password rules** (14 characters, 4 classes, history of 24) apply when passwords
  change, including root's. Key-only SSH logins are unaffected.
- **`cron.allow` and `at.allow`** start empty, so only root can schedule jobs. Add users
  to these files as needed; the role keeps what you add.
- **Login banner** replaces `/etc/issue`, `/etc/issue.net` and `/etc/motd`
  (`hardening_banner_text`).

## Ideas for later

- Separate roles per area once the single role grows
- Molecule tests on a full VM
- Central log shipping (journald → remote) for hosts without a cloud logging agent

## Requirements

- Python ≥ 3.12 and `make` on your machine
- Docker and `curl` (only for `make test`)
- Target servers: Debian 13 with SSH access and sudo
