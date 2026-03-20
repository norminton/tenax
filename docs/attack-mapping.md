# MITRE ATT&CK Mapping

## Overview

Tenax aligns Linux persistence detection with the MITRE ATT&CK framework.

However, it is important to understand:

> **Not all persistence mechanisms map cleanly to a single ATT&CK technique.**

Many Linux persistence methods:
- overlap multiple techniques
- span persistence, privilege escalation, and defense evasion
- represent execution surfaces rather than discrete techniques

Tenax maps each module to:
- Primary ATT&CK techniques (when applicable)
- Related techniques (where overlap exists)

---

## Core Persistence Mappings

### Cron
- **T1053.003 – Scheduled Task/Job: Cron**

**Description:**
Adversaries use cron jobs to execute commands or scripts at scheduled intervals.

**Relevance:**
- Periodic execution
- Low-complexity persistence
- Common in both benign and malicious use

---

### At Jobs
- **T1053 – Scheduled Task/Job (General)**

**Description:**
One-time or delayed task execution using `at` or `batch`.

**Relevance:**
- Less visible than cron
- Often used for delayed execution

---

### Systemd
- **T1543 – Create or Modify System Process**
- **T1543.002 – Systemd Service**

**Description:**
Adversaries create or modify systemd units to maintain persistence.

**Relevance:**
- Boot-time execution
- Service-level persistence
- High privilege potential

---

### RC / Init Scripts
- **T1037.004 – Boot or Logon Initialization Scripts: RC Scripts**

**Description:**
Execution via legacy initialization scripts.

**Relevance:**
- Still present on many systems
- Often overlooked

---

### Shell Profiles
- **T1546.004 – Event Triggered Execution: Unix Shell Configuration Modification**

**Description:**
Execution triggered by shell startup files (e.g., `.bashrc`).

**Relevance:**
- User-level persistence
- Triggered during login or shell spawn

---

### SSH Authorized Keys
- **T1098.004 – Account Manipulation: SSH Authorized Keys**

**Description:**
Adversaries add SSH keys for persistent access.

**Relevance:**
- Credential-less access
- Often bypasses password controls

---

### Sudoers
- **T1548 – Abuse Elevation Control Mechanism**

**Description:**
Modifying sudo rules to enable privilege escalation or persistence.

**Relevance:**
- Enables persistent privileged access
- Often combined with other techniques

---

### PAM (Pluggable Authentication Modules)
- **T1546 – Event Triggered Execution**
- **T1556 – Modify Authentication Process**

**Description:**
Manipulating authentication modules to execute code or bypass controls.

**Relevance:**
- High-impact
- Executes during authentication events

---

### Network Hooks
- **T1546 – Event Triggered Execution**

**Description:**
Execution triggered by network interface events.

**Relevance:**
- Conditional execution
- Low visibility

---

### Environment Hooks
- **T1574 – Hijack Execution Flow**

**Description:**
Manipulating environment variables to alter execution behavior.

**Relevance:**
- Indirect execution control
- Often used in combination with other techniques

---

### LD_PRELOAD / Dynamic Linker Abuse
- **T1574.006 – Hijack Execution Flow: Dynamic Linker Hijacking**

**Description:**
Injecting malicious libraries into process execution.

**Relevance:**
- Extremely stealthy
- Executes within trusted binaries

---

### Capabilities
- **T1548 – Abuse Elevation Control Mechanism**

**Description:**
Assigning Linux capabilities to enable privileged actions without root.

**Relevance:**
- Enables stealth privilege escalation
- Often overlooked in traditional analysis

---

### Autostart Hooks
- **T1547 – Boot or Logon Autostart Execution**

**Description:**
Execution triggered by desktop/session startup mechanisms.

**Relevance:**
- User-level persistence
- Common in desktop environments

---

### Containers
- **T1543.005 – Create or Modify System Process: Container Service**

**Description:**
Persistence via container services or runtime configuration.

**Relevance:**
- Increasingly common in modern environments
- May evade traditional host analysis

---

### Tmp Paths (Execution Context)
- **T1059 – Command and Scripting Interpreter**
- **T1105 – Ingress Tool Transfer**

**Description:**
Use of temporary directories for payload staging and execution.

**Relevance:**
- High correlation with malicious activity
- Not persistence itself, but strongly linked

---

## Important Distinction

Tenax differentiates between:

### Direct Persistence Techniques
- Cron
- Systemd
- SSH keys
- Shell profiles

### Persistence-Enabling Mechanisms
- Sudoers
- Capabilities
- PAM

### Execution Surfaces
- Tmp paths
- Environment variables
- Network hooks

This distinction is critical for accurate analysis.

---

## Analytical Takeaway

ATT&CK provides a taxonomy.

Tenax provides:
- **context**
- **prioritization**
- **execution-focused analysis**

> **ATT&CK tells you what is possible.  
Tenax helps you determine what is likely happening.**