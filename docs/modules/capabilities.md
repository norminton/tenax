# Linux Capabilities Persistence

## Overview

Linux capabilities are a fine-grained privilege model that allows specific binaries to perform privileged operations without requiring full root privileges.

Instead of granting full superuser access, capabilities allow programs to be assigned individual privileges such as:

- binding to low ports  
- modifying network settings  
- reading sensitive files  
- executing privileged operations  

Capabilities are assigned to binaries using:

```text
setcap
```

And viewed using:

```text
getcap
```

> **Capabilities allow non-root binaries to perform actions normally restricted to root.**

While designed for security and least privilege, capabilities can be abused by attackers to:

- maintain elevated execution  
- bypass traditional privilege controls  
- establish stealthy persistence  

---

## Why Attackers Use Capabilities for Persistence

Attackers use capabilities because they provide:

- Privileged execution without root login  
- Persistence tied to a binary rather than a config file  
- Stealth compared to SUID binaries  
- Compatibility with existing system tools  
- A mechanism often overlooked in triage  

Capabilities are especially useful when:

- attackers lose root access  
- access must persist under a normal user  
- traditional persistence mechanisms are monitored  

---

## Execution Semantics

Capabilities are stored as extended attributes on files.

Example:

```text
setcap cap_net_bind_service=+ep /usr/bin/python3
```

This allows `python3` to:

- bind to privileged ports (<1024)  
- without requiring root  

Capabilities are applied at execution time:

1. Binary is executed  
2. Kernel reads extended attributes  
3. Capabilities are applied to process  
4. Process gains specific privileged behavior  

---

## Capability Types (Simplified)

Capabilities are grouped into categories such as:

- `cap_setuid` → change user ID  
- `cap_setgid` → change group ID  
- `cap_net_admin` → network control  
- `cap_net_bind_service` → bind low ports  
- `cap_dac_read_search` → bypass file permissions  

Some capabilities are extremely dangerous.

---

## Why This Mechanism Is So Effective

Capabilities are powerful because they:

- do not require modifying system startup  
- do not rely on scheduled execution  
- are attached directly to binaries  
- persist across reboots  
- are difficult to notice without explicit checks  

Unlike SUID:
- less obvious  
- more granular  
- often ignored  

> **The persistence lives in the binary’s metadata, not in a configuration file.**

---

## Common Attacker Tradecraft

### 1. Granting `cap_setuid` to a Binary for Privilege Escalation

Example:

```text
setcap cap_setuid+ep /usr/bin/python3
```

Execution flow:
1. Attacker gains root access  
2. Assigns capability to Python binary  
3. Drops privileges or waits  
4. Runs Python as normal user  
5. Uses Python to escalate back to root  

Example usage:

```python
import os
os.setuid(0)
os.system("/bin/bash")
```

Why attackers use this:
- Persistent privilege escalation path  
- No need for SUID  
- Works from normal user context  

---

### 2. Backdoored Custom Binary with Capabilities

Example:

```text
cp /bin/bash /usr/local/bin/.helper
setcap cap_setuid+ep /usr/local/bin/.helper
```

Execution flow:
1. Attacker copies legitimate binary  
2. Assigns privilege capability  
3. Places binary in hidden path  
4. Executes binary later for root shell  

Why attackers use this:
- Avoids modifying system binaries  
- Easier to hide  
- Controlled access to privilege escalation  

---

### 3. Capability Abuse on Interpreters (Python, Perl, etc.)

Example:

```text
setcap cap_setuid+ep /usr/bin/perl
```

Execution flow:
1. Attacker assigns capability to interpreter  
2. Executes interpreter as normal user  
3. Runs script to escalate privileges  

Why attackers use this:
- Interpreters provide flexible execution  
- Easy to run custom payloads  
- Blends with normal system tools  

---

### 4. Network Capability Abuse for Backdoor Services

Example:

```text
setcap cap_net_bind_service+ep /usr/bin/python3
```

Execution flow:
1. Attacker grants ability to bind low ports  
2. Runs backdoor on port 80 or 443  
3. Avoids needing root to open privileged ports  

Why attackers use this:
- Enables stealthy network listeners  
- Avoids privileged process monitoring  
- Blends with legitimate services  

---

### 5. File Access Bypass via `cap_dac_read_search`

Example:

```text
setcap cap_dac_read_search+ep /usr/bin/cat
```

Execution flow:
1. Attacker assigns capability  
2. Uses binary to read restricted files  
3. Accesses sensitive data without root  

Why attackers use this:
- Bypasses file permission checks  
- Enables credential or data access  
- Useful for lateral movement  

---

### 6. Persistence via Hidden Capability-Enabled Binary

Example:

```text
setcap cap_setuid+ep /home/user/.cache/.bin
```

Execution flow:
1. Attacker places binary in hidden location  
2. Assigns capability  
3. Leaves system  
4. Returns later and executes binary  
5. Gains elevated privileges  

Why attackers use this:
- No visible config changes  
- Hidden in user-controlled path  
- Persistent across reboots  

---

### 7. Capability Backdoor on Common System Binary

Example:

```text
setcap cap_setuid+ep /usr/bin/vim
```

Execution flow:
1. Attacker modifies common tool  
2. User runs tool normally  
3. Attacker leverages capability for escalation  

Why attackers use this:
- High likelihood binary will be executed  
- Blends into normal usage  
- Hard to detect without capability inspection  

---

### 8. Combining Capabilities with Other Persistence Mechanisms

Example chain:
- autostart launches Python  
- Python has `cap_setuid`  
- Python escalates to root  
- root-level persistence is restored  

Execution flow:
1. Initial persistence triggers execution  
2. Capability-enabled binary escalates privileges  
3. Additional persistence is re-established  

Why attackers use this:
- Combines persistence + privilege escalation  
- Enables layered attack chains  
- Increases resilience  

---

## What Normal Looks Like

Legitimate capabilities are typically:

- assigned by packages  
- limited in scope  
- applied to specific system binaries  

Examples:

```text
/usr/bin/ping = cap_net_raw+ep
```

Normal characteristics:

- expected binaries  
- known capabilities  
- consistent with system function  

---

## What Malicious Use Looks Like

### High-Signal Indicators

- `cap_setuid` or `cap_setgid` on unusual binaries  
- capabilities on:
  - interpreters (python, perl)  
  - shells  
  - user-writable paths  
- hidden binaries with capabilities  
- unexpected capability assignments  

### Medium-Signal Indicators

- uncommon binaries with capabilities  
- recently modified capability assignments  
- capability mismatch with binary purpose  

### Low-Signal Indicators

- standard system capabilities  
- package-managed assignments  

---

## ATT&CK Mapping

Relevant ATT&CK techniques include:

- **T1548 – Abuse Elevation Control Mechanism**
- **T1548.001 – Setuid and Setgid**

Capabilities are conceptually similar to SUID abuse but provide a more granular and stealthy mechanism.

---

## Why Analysts Miss This Technique

### 1. Not Visible in Standard Listings

Capabilities do not appear in:

- `ls -l`  
- typical file listings  

### 2. Requires Explicit Enumeration

Analysts must run:

```text
getcap -r / 2>/dev/null
```

### 3. Less Known Than SUID

Most analysts check SUID binaries, but not capabilities.

### 4. Stored in Extended Attributes

Capabilities are not stored in normal file metadata.

---

## Deep Analytical Guidance

### Key Question

> Does this binary have privileges that exceed what it should be allowed to do?

---

### Focus Areas

#### 1. Capability Enumeration

```text
getcap -r / 2>/dev/null
```

#### 2. Binary Purpose

- Does the capability make sense for the binary?  

#### 3. Path Trust

- Is the binary in a trusted system directory?  
- Is it user-writable?  

#### 4. Capability Type

- `cap_setuid` → HIGH RISK  
- `cap_dac_read_search` → HIGH RISK  
- network capabilities → MEDIUM  

---

## Triage Workflow

1. Enumerate all capabilities  

2. Identify high-risk capabilities  

3. Inspect binaries  

4. Check file metadata:

```text
stat <binary>
```

5. Validate package ownership  

6. Correlate with execution activity  

---

## Evidence to Preserve

- capability listings  
- affected binaries  
- file metadata  
- hashes  
- execution artifacts  

---

## Why Tenax Checks This Surface

Tenax checks capabilities because they:

- provide stealthy privilege escalation  
- persist across reboots  
- are frequently overlooked  
- enable chaining with other persistence mechanisms  

> Capabilities turn ordinary binaries into privileged execution tools without obvious indicators.

---

## Key Takeaway

Linux capabilities are a stealthy persistence and privilege escalation mechanism.

> The attacker does not need root access continuously — they only need a binary that can become root when executed.
