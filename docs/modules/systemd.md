# Systemd Persistence

## Overview

Systemd is the dominant service manager and initialization system on modern Linux distributions. It is responsible for orchestrating system startup, managing long-running services, and handling dependencies between system components.

Because of its central role in system execution, systemd represents one of the most powerful and reliable persistence mechanisms available to an adversary.

> **If an attacker can control systemd, they can control what executes on boot, under which privileges, and under what conditions.**

---

## Why Attackers Use Systemd for Persistence

Systemd provides adversaries with:

- **Guaranteed execution at boot**
- **Fine-grained control over execution conditions**
- **Integration with legitimate system services**
- **High survivability across reboots**
- **Execution as root or privileged service accounts**

Unlike simpler mechanisms such as cron, systemd allows attackers to embed persistence into what appears to be legitimate system functionality.

---

## Execution Semantics

Systemd operates through **unit files**, typically located in:

- `/etc/systemd/system/` (administrator-defined)
- `/lib/systemd/system/` or `/usr/lib/systemd/system/` (package-managed)

Each unit defines:
- What to execute (`ExecStart`)
- When to execute (`WantedBy`, `After`, `Before`)
- How to execute (user, restart policy, environment)

### Key Execution Properties

- **Boot-triggered execution** via targets such as:
  - `multi-user.target`
  - `graphical.target`

- **Automatic restart behavior**:
  - `Restart=always`
  - `Restart=on-failure`

- **Execution context**:
  - Root (default for system units)
  - Specific users via `User=`

---

## Privilege Requirements

- Writing to `/etc/systemd/system/` requires **root privileges**
- User-level persistence is possible via:
  - `~/.config/systemd/user/`

However, most high-value persistence involves **system-level units**.

---

## Common Attacker Tradecraft

### 1. Malicious Service Creation

Attackers create new services that execute payloads:

```ini
[Service]
ExecStart=/tmp/update.sh
Restart=always