# Sudoers Persistence and Privilege Abuse

## Overview

The `sudoers` configuration controls which users can execute commands with elevated privileges on a Linux system. It is a central component of privilege delegation and administrative access control.

While `sudoers` is not a persistence mechanism in the traditional sense, it is one of the most powerful **persistence-enabling mechanisms** available to an adversary.

> **Sudoers does not guarantee execution — it guarantees privilege.**

---

## Why Attackers Use Sudoers for Persistence

Sudoers provides adversaries with:

- Persistent privilege escalation  
- The ability to execute commands as root without authentication  
- Control over which binaries can be executed with elevated privileges  
- Long-term survivability tied to account access  
- A mechanism to maintain dominance even if initial persistence is removed  

Unlike cron or systemd, sudoers does not execute code automatically. Instead, it ensures that **when execution occurs, it can occur with elevated privileges**.

---

## Execution Semantics

Sudoers rules define:

- Which users can run commands  
- Which commands can be executed  
- Whether a password is required  

Common locations:

- `/etc/sudoers`
- `/etc/sudoers.d/`

### Rule Structure

```
user ALL=(ALL) NOPASSWD: /bin/bash
```

Breakdown:

- `user` → the account granted privileges  
- `ALL=(ALL)` → allowed hosts and target users  
- `NOPASSWD` → no authentication required  
- `/bin/bash` → command allowed to execute  

---

## Privilege Requirements

- Modifying `/etc/sudoers` requires root  
- Files in `/etc/sudoers.d/` also require root  

Sudoers abuse typically occurs:
- After privilege escalation  
- During post-exploitation persistence  

---

## Common Attacker Tradecraft

### 1. Granting Full Root Access

Example:

```
user ALL=(ALL) NOPASSWD: ALL
```

Why this works:
- Grants unrestricted root access  
- Eliminates need for further escalation  

---

### 2. Granting Shell Execution

Example:

```
user ALL=(ALL) NOPASSWD: /bin/bash
```

Why attackers use this:
- Direct root shell access  
- Minimal detection compared to broader rules  

---

### 3. Abusing Specific Binaries

Example:

```
user ALL=(ALL) NOPASSWD: /usr/bin/vim
```

Why attackers use this:
- Some binaries allow shell escape  
- Appears more restrictive and legitimate  

---

### 4. Backdooring Existing Rules

Example:

- Modifying an existing admin rule  
- Adding additional commands  

Why attackers use this:
- Reduces visibility  
- Blends into existing configuration  

---

### 5. Persistence via Secondary Accounts

Example:

- Creating a new user  
- Granting sudo privileges  

Why attackers use this:
- Maintains access even if original account is removed  

---

## What Normal Looks Like

Legitimate sudoers usage typically involves:

- Clearly defined administrative users  
- Limited command scope  
- Password requirements for sensitive actions  
- Minimal use of `NOPASSWD`  

Example:

```
admin ALL=(ALL) ALL
```

---

## What Malicious Use Looks Like

### High-Signal Indicators

- `NOPASSWD: ALL`  
- Shell execution (`/bin/bash`, `/bin/sh`)  
- Rules granting broad or unrestricted access  
- Recently modified sudoers files  

### Medium-Signal Indicators

- Access to unusual binaries  
- Expansion of existing rules  
- New files in `/etc/sudoers.d/`  

### Low-Signal Indicators

- Legitimate admin delegation  
- Automation-related rules  

---

## ATT&CK Mapping

- **T1548 – Abuse Elevation Control Mechanism**

Sudoers abuse falls under:
- Privilege escalation  
- Persistence enablement  
- Defense evasion (in some cases)  

---

## Procedure Examples (Tradecraft)

Typical attacker workflow:

```
echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/backdoor
chmod 440 /etc/sudoers.d/backdoor
```

Execution flow:
1. Gain root access  
2. Modify sudoers  
3. Maintain persistent privilege escalation  

---

## Analytical Guidance

### Key Question

> Does this rule grant more privilege than is necessary for this user?

---

### Focus Areas

1. Scope of Access  
   - Is access unrestricted?  
   - Are commands overly broad?  

2. Authentication Requirements  
   - Is `NOPASSWD` used?  
   - Should authentication be required?  

3. Command Selection  
   - Do allowed binaries enable shell escape?  

4. File Integrity  
   - Has the sudoers file been modified recently?  

5. User Context  
   - Is the user expected to have elevated privileges?  

---

## Triage Workflow

1. Inspect sudoers file:

```
cat /etc/sudoers
ls /etc/sudoers.d/
```

2. Review additional rules:

```
cat /etc/sudoers.d/*
```

3. Identify suspicious entries  

4. Validate file metadata:

```
stat /etc/sudoers
stat /etc/sudoers.d/*
```

5. Correlate with user activity  

---

## Evidence to Preserve

- `/etc/sudoers` contents  
- `/etc/sudoers.d/` files  
- File metadata (timestamps, ownership)  
- User account information  
- Command execution logs  

---

## False Positive Reduction

To reduce false positives:

- Understand organizational privilege policies  
- Validate legitimate administrative access  
- Review automation and configuration management tools  
- Confirm with system owners  

---

## Why Tenax Checks This Surface

Sudoers provides:

- Persistent privilege control  
- Indirect persistence through privilege escalation  
- A foundation for other persistence mechanisms  

It is a critical component of post-exploitation stability.

> An attacker with persistent sudo access does not need to persist execution — they can recreate it at will.

---

## Key Takeaway

Sudoers persistence is about controlling privilege, not execution.

> The attacker does not need persistence if they can always become root.
