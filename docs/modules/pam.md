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

### 1. Malicious PAM Module Injection

Example:

```text
auth required /lib/security/pam_backdoor.so
```

Execution flow:
1. Attacker writes or installs a malicious PAM module  
2. PAM configuration is modified to include the module  
3. User attempts to authenticate (e.g., SSH or sudo)  
4. Malicious module executes during authentication  

Why attackers use this:
- Executes every time authentication occurs  
- Can capture credentials or alter behavior  
- Extremely persistent and high-value  

---

### 2. Credential Harvesting via PAM Hook

Example behavior:

A malicious module intercepts authentication functions and logs credentials.

Execution flow:
1. User attempts login or runs `sudo`  
2. PAM module receives username and password  
3. Credentials are written to a hidden file (e.g., `/tmp/.credlog`)  
4. Authentication proceeds normally to avoid suspicion  

Why attackers use this:
- Stealthy credential capture  
- No need for keyloggers  
- Works across multiple services  

---

### 3. Backdooring Authentication Logic

Example:

```text
auth sufficient pam_backdoor.so
```

Execution flow:
1. Attacker inserts custom PAM module  
2. Module allows authentication with attacker-defined credentials  
3. PAM stack continues or short-circuits based on control flag  
4. Attacker gains access without valid credentials  

Why attackers use this:
- Bypass authentication entirely  
- Maintain access even if passwords change  
- Extremely difficult to detect without config inspection  

---

### 4. Modifying Existing PAM Configuration

Example:

```text
auth required pam_unix.so
auth optional pam_exec.so /tmp/script.sh
```

Execution flow:
1. Attacker modifies existing PAM configuration  
2. Adds execution hook using legitimate module (`pam_exec.so`)  
3. Script executes during authentication events  
4. Malicious logic runs under authentication context  

Why attackers use this:
- Blends into existing configuration  
- Avoids introducing new modules  
- Uses legitimate PAM functionality  

---

### 5. Persistence via `pam_exec.so`

Example:

```text
auth optional pam_exec.so /tmp/hook.sh
```

Execution flow:
1. PAM executes external script during authentication  
2. Script runs every time authentication occurs  
3. Attacker gains repeated execution opportunities  

Why attackers use this:
- No custom binary required  
- Uses built-in PAM functionality  
- Easier to deploy than compiled modules  

---

### 6. Targeting Specific Services (e.g., SSH)

Example:

File: `/etc/pam.d/sshd`

```text
auth required pam_backdoor.so
```

Execution flow:
1. Attacker modifies SSH PAM configuration  
2. Only SSH authentication is affected  
3. Credentials or access are controlled via PAM module  
4. Persistence is scoped to remote access  

Why attackers use this:
- Focuses on high-value access paths  
- Reduces visibility compared to global changes  
- Targets administrator behavior  

---

### 7. Stealth Through Control Flags

Example:

```text
auth sufficient pam_backdoor.so
auth required pam_unix.so
```

Execution flow:
1. PAM module executes first  
2. If attacker condition is met → authentication succeeds  
3. If not → normal authentication continues  
4. User sees no disruption  

Why attackers use this:
- Avoids breaking login functionality  
- Reduces detection risk  
- Maintains normal system behavior  

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
