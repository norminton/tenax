# SSH Authorized Keys Persistence

## Overview

SSH (Secure Shell) is a primary method of remote access for Linux systems. It allows users to authenticate using passwords or cryptographic key pairs.

Persistence via SSH typically involves modifying the `authorized_keys` file to grant continued access without requiring credentials.

> **SSH persistence does not execute code — it preserves access.**

---

## Why Attackers Use SSH for Persistence

SSH persistence provides adversaries with:

- Password-less access to compromised systems  
- Reliable and direct remote entry  
- Independence from execution-based persistence mechanisms  
- Low operational noise  
- Compatibility with legitimate administrative workflows  

Unlike cron or systemd, SSH persistence ensures the attacker can **return at will**, rather than relying on automated execution.

---

## Execution Semantics

SSH uses public key authentication via the `authorized_keys` file.

Common locations:

- `~/.ssh/authorized_keys` (user-specific)
- `/root/.ssh/authorized_keys` (root access)

### Authentication Flow

1. Client connects via SSH  
2. Server checks `authorized_keys`  
3. If matching key is found:
   - Access is granted  
   - No password required  

### Execution Context

- Executes under the associated user account  
- Can be combined with privilege escalation techniques  

---

## Privilege Requirements

- User-level persistence:
  - Requires access to user account  

- Root-level persistence:
  - Requires root privileges  

SSH persistence is often established:
- After initial compromise  
- After privilege escalation  

---

## Common Attacker Tradecraft

### 1. Adding a Malicious SSH Key

Example:

```
ssh-rsa AAAAB3NzaC1fakekey attacker@host
```

Why this works:
- Grants direct access without credentials  
- Difficult to detect without inspection  

---

### 2. Command Execution via SSH Key Options

Example:

```
command="/bin/bash -i" ssh-rsa AAAAB3NzaC1fakekey attacker@host
```

Why attackers use this:
- Forces execution of specific commands  
- Enables shell spawning or backdoors  

---

### 3. Restricting Visibility

Example:

```
from="192.168.1.100" ssh-rsa AAAAB3NzaC1fakekey attacker@host
```

Why attackers use this:
- Limits access to specific IPs  
- Reduces detection risk  

---

### 4. Persistence in Root Account

Path:

```
/root/.ssh/authorized_keys
```

Why attackers use this:
- Provides full system control  
- Eliminates need for privilege escalation  

---

### 5. Key Masquerading

Example:

- Comment fields mimicking legitimate users  
- Keys labeled as backups or automation  

Why attackers use this:
- Blend into existing keys  
- Avoid raising suspicion  

---

## What Normal Looks Like

Legitimate SSH usage typically involves:

- Keys associated with known users  
- Properly labeled key comments  
- Restricted file permissions (`600`)  
- Minimal use of advanced options  

Example:

```
ssh-rsa AAAAB3NzaC1realkey user@laptop
```

---

## What Malicious Use Looks Like

### High-Signal Indicators

- Unknown or unrecognized SSH keys  
- Keys added to root account  
- Keys with forced command execution  
- Keys with unusual options (command=, environment=)  
- Recently modified `authorized_keys` file  

### Medium-Signal Indicators

- Keys without identifiable comments  
- Keys from unknown sources  
- Multiple keys added in short timeframes  

### Low-Signal Indicators

- Additional keys for legitimate automation  
- Key rotation or infrastructure changes  

---

## ATT&CK Mapping

- **T1098.004 – Account Manipulation: SSH Authorized Keys**

SSH persistence falls under:
- Account manipulation  
- Credential abuse  
- Persistent access mechanisms  

---

## Procedure Examples (Tradecraft)

Typical attacker workflow:

```
echo "ssh-rsa AAAAB3NzaC1fakekey attacker@host" >> ~/.ssh/authorized_keys
```

Execution flow:
1. Gain access to system  
2. Add SSH key  
3. Disconnect  
4. Reconnect at any time without credentials  

---

## Analytical Guidance

### Key Question

> Does this key belong to a legitimate user or trusted system?

---

### Focus Areas

1. Key Ownership  
   - Who owns the account?  
   - Is the key expected?  

2. Key Metadata  
   - Comment field  
   - Key origin  

3. File Integrity  
   - Has the file been modified recently?  

4. Key Options  
   - Are there forced commands?  
   - Are restrictions applied?  

5. Access Patterns  
   - Are there unusual login times or sources?  

---

## Triage Workflow

1. Inspect authorized keys:

```
cat ~/.ssh/authorized_keys
cat /root/.ssh/authorized_keys
```

2. Identify unknown keys  

3. Review file metadata:

```
stat ~/.ssh/authorized_keys
```

4. Check login history:

```
last
```

5. Correlate with network logs  

---

## Evidence to Preserve

- `authorized_keys` file contents  
- File metadata (timestamps, ownership)  
- SSH logs (`/var/log/auth.log`, `/var/log/secure`)  
- Known user key inventory  

---

## False Positive Reduction

To reduce false positives:

- Maintain inventory of approved SSH keys  
- Validate keys with system owners  
- Review infrastructure automation systems  
- Correlate with known administrative access patterns  

---

## Why Tenax Checks This Surface

SSH persistence provides:

- Direct, reliable access  
- No dependency on execution mechanisms  
- High stealth when properly disguised  

It is one of the most effective persistence methods in Linux environments.

> If an attacker controls SSH access, they do not need persistence — they already have it.

---

## Key Takeaway

SSH persistence is about maintaining access, not executing code.

> The attacker does not need to run anything — they just need to log back in.
