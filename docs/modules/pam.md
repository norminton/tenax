# PAM Persistence and Authentication Hooking

## Overview

Pluggable Authentication Modules (PAM) provide a flexible framework for handling authentication, authorization, and session management in Linux systems.

PAM is responsible for controlling how users authenticate to services such as:

- SSH
- sudo
- login
- su
- graphical login managers

Because PAM sits directly in the authentication flow, it represents one of the most powerful persistence and credential access mechanisms available to an adversary.

> **PAM persistence does not wait for execution — it intercepts trust at the moment it is granted.**

---

## Why Attackers Use PAM for Persistence

PAM provides adversaries with:

- Execution during authentication events  
- Access to plaintext credentials  
- Control over authentication success/failure  
- Integration into trusted system workflows  
- High stealth when modified subtly  

Unlike cron or systemd, PAM persistence triggers when:

- a user logs in  
- a user runs `sudo`  
- a service authenticates a user  

This makes PAM one of the highest-value persistence surfaces in Linux.

---

## Execution Semantics

PAM operates through configuration files that define authentication stacks.

Common locations:

- `/etc/pam.d/`
- `/etc/pam.conf`

Each service (e.g., `sshd`, `sudo`, `login`) has its own PAM configuration file.

### Example Structure

```text
auth required pam_unix.so
account required pam_unix.so
session required pam_unix.so
```

Each line defines:

- module type (`auth`, `account`, `session`, `password`)
- control flag (`required`, `optional`, `sufficient`)
- module (`pam_unix.so`, etc.)

### Key Concept

PAM modules are executed **in sequence** during authentication.

If an attacker inserts a malicious module:

- it will execute during authentication  
- it may capture credentials  
- it may alter authentication behavior  

---

## Privilege Requirements

- Modifying PAM configuration requires root access  
- Installing malicious PAM modules requires root  

This means PAM persistence typically occurs:

- after privilege escalation  
- during post-exploitation  

---

## Why This Mechanism Is So Powerful

PAM is powerful because it operates at the point where:

- trust is established  
- credentials are handled  
- access is granted  

This allows attackers to:

- capture passwords in plaintext  
- bypass authentication controls  
- maintain persistence without obvious execution artifacts  

Unlike other mechanisms:

- no scheduled task is needed  
- no service needs to be created  
- no user interaction beyond normal login is required  

---

## Common Attacker Tradecraft

### 1. System-Wide Credential Logging via PAM Module Injection

Target file:

```text
/etc/pam.d/sshd
```

Example modification:

```text
auth required /lib/security/pam_backdoor.so
```

Execution flow:
1. Attacker drops malicious module:
   ```text
   /lib/security/pam_backdoor.so
   ```
2. Modifies SSH PAM configuration  
3. User attempts SSH login  
4. Malicious module executes during authentication  
5. Credentials are captured and logged  

Why attackers use this:
- Executes on every SSH login  
- Captures plaintext credentials  
- Extremely persistent  

---

### 2. Credential Logging Using `pam_exec.so`

Target file:

```text
/etc/pam.d/sudo
```

Example modification:

```text
auth optional pam_exec.so /tmp/log.sh
```

Malicious script:

```bash
#!/bin/bash
echo "$(date) $(whoami)" >> /tmp/.log
```

Execution flow:
1. Attacker adds `pam_exec.so` line  
2. User runs `sudo`  
3. PAM executes `/tmp/log.sh`  
4. Script logs activity or credentials  

Why attackers use this:
- No custom binary required  
- Easy to deploy  
- Blends with legitimate PAM modules  

---

### 3. Password Capture via `pam_exec.so` (Real Tradecraft)

Target file:

```text
/etc/pam.d/sshd
```

Example:

```text
auth optional pam_exec.so expose_authtok /tmp/cred.sh
```

Malicious script:

```bash
#!/bin/bash
read password
echo "$(date) $PAM_USER:$password" >> /tmp/.creds
```

Execution flow:
1. User attempts SSH login  
2. PAM passes password to script via `expose_authtok`  
3. Script captures credentials  
4. Authentication continues normally  

Why attackers use this:
- Direct plaintext password capture  
- No need for kernel/rootkits  
- Very stealthy  

---

### 4. Backdoor Authentication (Bypass Password)

Target file:

```text
/etc/pam.d/sshd
```

Example:

```text
auth sufficient /lib/security/pam_backdoor.so
auth required pam_unix.so
```

Execution flow:
1. Attacker installs malicious module  
2. Module checks for attacker password/key  
3. If matched → authentication succeeds  
4. If not → normal auth continues  

Why attackers use this:
- Silent authentication bypass  
- Does not break normal logins  
- Hard to detect during casual inspection  

---

### 5. Persistence via `/etc/pam.d/common-auth` (Debian/Ubuntu)

Target file:

```text
/etc/pam.d/common-auth
```

Example:

```text
auth optional pam_exec.so /tmp/hook.sh
```

Execution flow:
1. Attacker modifies shared PAM stack  
2. Affects multiple services:
   - SSH  
   - sudo  
   - login  
3. Script executes on all authentication events  

Why attackers use this:
- Broad coverage  
- Single change impacts multiple services  
- High execution frequency  

---

### 6. Stealthy Logging via Existing Module Modification

Target file:

```text
/etc/pam.d/sudo
```

Example:

```text
auth required pam_unix.so
auth optional pam_exec.so /usr/local/bin/.hidden.sh
```

Execution flow:
1. Attacker appends execution line after legit module  
2. User runs `sudo`  
3. Legit auth happens  
4. Malicious script executes silently  

Why attackers use this:
- Blends into normal config  
- Less suspicious than replacing modules  
- Maintains system stability  

---

### 7. Malicious Module Placement in Legitimate Path

Example:

```text
/lib/security/pam_unix.so   ← replaced with malicious version
```

Execution flow:
1. Attacker replaces legitimate PAM module  
2. All services using `pam_unix.so` are affected  
3. Credentials are intercepted globally  
4. System behaves normally otherwise  

Why attackers use this:
- Massive coverage  
- No config changes required  
- Extremely stealthy  

---

### 8. Targeting Root Authentication Paths

Target file:

```text
/etc/pam.d/su
```

Example:

```text
auth optional pam_exec.so /tmp/root_hook.sh
```

Execution flow:
1. Attacker targets `su` usage  
2. Admin attempts privilege escalation  
3. Script executes during authentication  
4. Root-level activity is captured  

Why attackers use this:
- Targets high-value actions  
- Captures privileged behavior  
- Useful for lateral movement    

---


## What Normal Looks Like

Legitimate PAM configurations typically:

- Use standard modules (`pam_unix.so`, `pam_env.so`, `pam_limits.so`)  
- Have consistent structure across systems  
- Do not reference:
  - `/tmp`
  - `/dev/shm`
  - user home directories  
- Do not execute arbitrary scripts  

Example:

```text
auth required pam_unix.so
account required pam_unix.so
session required pam_unix.so
```

---

## What Malicious Use Looks Like

### High-Signal Indicators

- Unknown PAM modules (`.so` files)  
- References to:
  - `/tmp`
  - `/dev/shm`
  - user-controlled paths  
- Use of `pam_exec.so` with suspicious scripts  
- Recently modified PAM configuration files  
- Authentication anomalies  

### Medium-Signal Indicators

- Additional or reordered PAM entries  
- Unusual control flags (`optional`, `sufficient`)  
- Service-specific configuration changes  

### Low-Signal Indicators

- Legitimate PAM customization  
- Enterprise authentication integrations  
- MFA modules  

---

## ATT&CK Mapping

- **T1556 – Modify Authentication Process**

PAM persistence directly maps to:
- authentication manipulation  
- credential access  
- persistence via trust interception  

---

## Why Analysts Miss This Technique

### 1. PAM Is Not Well Understood

Many analysts know it exists but do not understand how it works.

### 2. Configuration Looks Complex

PAM configs appear dense and administrative.

### 3. No Obvious Execution Trigger

There is no cron job or service — execution is tied to authentication.

### 4. Changes Can Be Subtle

A single line added to a PAM config can create persistence.

---

## Deep Analytical Guidance

### Key Question

> Is authentication behavior being altered or intercepted in a way that benefits an attacker?

---

### Focus Areas

#### 1. Module Origin

- Is the module legitimate?
- Is it package-managed?

#### 2. Execution Behavior

- Does the module execute external scripts?
- Does it alter authentication flow?

#### 3. Configuration Changes

- Are there new or reordered entries?
- Do control flags make sense?

#### 4. Scope

- Does this affect:
  - SSH?
  - sudo?
  - all logins?

#### 5. Credential Exposure Risk

- Could this module capture or log credentials?

---

## Triage Workflow

1. Inspect PAM configurations:

```text
ls /etc/pam.d/
cat /etc/pam.d/*
```

2. Identify unknown modules  

3. Search for execution hooks:

```text
grep -R "pam_exec" /etc/pam.d/
```

4. Validate module files:

```text
stat /lib/security/*
```

5. Correlate with authentication logs:

```text
cat /var/log/auth.log
```

6. Investigate suspicious scripts or binaries  

---

## Evidence to Preserve

- `/etc/pam.d/*`
- `/etc/pam.conf`
- PAM module binaries (`.so`)
- referenced scripts
- file metadata (timestamps, ownership)
- authentication logs
- captured credential artifacts (if present)

---

## False Positive Reduction

To reduce false positives:

- Compare against baseline PAM configs  
- Validate modules with package manager  
- Understand enterprise authentication integrations  
- Confirm expected authentication behavior  

---

## Why Tenax Checks This Surface

PAM provides:

- direct access to authentication flows  
- credential visibility  
- execution during trust establishment  

It is one of the highest-value persistence mechanisms in Linux.

> If an attacker controls PAM, they control who is allowed to become trusted.

---

## Key Takeaway

PAM persistence is about controlling authentication itself.

The attacker does not need to wait for execution.

> They position themselves at the exact moment access is granted — and take control of it.
