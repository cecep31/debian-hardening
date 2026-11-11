# Debian Hardening — Template (Ansible)

A small starter template that applies baseline security hardening to
**Debian 13 (trixie)** servers over SSH.
It is meant as a **first init** for new servers: sensible defaults, one role,
easy to read and extend.

> **Status:** template. It has only been tested in a throwaway Debian 13 container,
> never against a real server. Run `make plan` and read the diff before applying.

Based on selected controls from the **CIS Debian Linux Benchmark**, not a full implementation.

## What it does

| Area | Changes | Tag |
|---|---|---|
| SSH | No root login, keys only, no X11/agent/TCP forwarding, fewer auth tries, idle timeout | `ssh` |
| Firewall | nftables: drop all inbound except SSH and the ports you allow | `firewall` |
| Updates | `unattended-upgrades` for security patches (reboot off by default) | `updates` |
| Kernel | Network and kernel sysctl hardening, block rarely used modules | `kernel` |
| Brute force | fail2ban for SSH, using the systemd journal and nftables | `fail2ban` |
| Audit | auditd rules for identity files, sudo, SSH config, time, kernel modules | `auditd` |
| System | AppArmor and time sync on, core dumps off, umask 027, password ageing, sudo logging | `system` |
| Cleanup | Remove telnet, rsh, talk, nis | `packages` |

## Lockout protection

Before changing anything, the role stops if:

- the host is not Debian 13,
- you connect as `root` while root login is being disabled,
- your user has no `~/.ssh/authorized_keys` while password login is being disabled,
- your user is missing from `hardening_ssh_allow_users`,
- the firewall port lists are not lists of valid port numbers.

SSH stays allowed in the firewall on `hardening_ssh_port`, and the sshd config is
validated with `sshd -t` before SSH is reloaded.

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
| `hardening_ssh_port` | SSH port (stays open in the firewall) |
| `hardening_ssh_allow_users` | Only these users may log in over SSH (empty allows all) |
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
nothing, that bad port input is rejected, and that the resulting sshd, nftables and
fail2ban configs are valid. Containers have no systemd, so services are configured
but not started there.

## Good to know

- **Docker hosts.** The firewall flushes the whole ruleset and drops forwarded traffic,
  which breaks Docker networking. Leave `hardening_firewall_enabled: false` on Docker
  hosts or adapt the ruleset.
- **IPv6 router advertisements** are ignored (`accept_ra = 0`). Turn this off on hosts
  that get their IPv6 address through SLAAC.
- **TCP forwarding is off**, so SSH tunnels and port forwarding stop working.
  Set `hardening_ssh_allow_tcp_forwarding: true` if you need them.
- **Kernel modules** are blocked on next load; already loaded modules stay until reboot.

## Ideas for later

- Separate roles per area once the single role grows
- Molecule tests on a full VM
- AIDE file integrity monitoring
- Central log shipping (journald → remote)
- Login banner and stricter PAM settings (`pam_faillock`, `pwquality`)

## Requirements

- Python ≥ 3.12 and `make` on your machine
- Docker (only for `make test`)
- Target servers: Debian 13 with SSH access and sudo
