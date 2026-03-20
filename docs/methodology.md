
# Tenax Methodology

## Overview

Tenax is built on a simple but critical premise:

> **Linux persistence is not defined by files — it is defined by execution guarantees.**

Traditional approaches to persistence detection focus on enumerating known locations (cron, systemd, etc.). While this is necessary, it is not sufficient for high-confidence analysis.

Tenax instead models persistence as a function of **how and when code execution is guaranteed**, and evaluates artifacts based on:

- Execution trigger
- Privilege context
- Frequency of execution
- Survivability
- Analyst signal-to-noise ratio

---

## The Persistence Model

Tenax categorizes persistence mechanisms by their **execution model**, not just their file location.

### 1. Time-Based Execution
**Examples:** cron, at jobs  
**Behavior:** Executes at defined intervals or one-time schedules  

**Attacker Use:**
- Periodic beaconing
- Re-establishing access
- Staging payload retrieval

**Key Insight:**
Time-based persistence is reliable but often noisy and easier to detect if improperly disguised.

---

### 2. Boot-Time Execution
**Examples:** systemd, rc/init scripts  
**Behavior:** Executes during system initialization  

**Attacker Use:**
- Establishing foothold immediately after reboot
- Running long-lived services
- Embedding into legitimate service frameworks

**Key Insight:**
Boot persistence offers high survivability and strong privilege guarantees.

---

### 3. Logon / Shell Execution
**Examples:** shell profiles, SSH authorized_keys, autostart hooks  
**Behavior:** Executes when a user logs in or starts a shell  

**Attacker Use:**
- User-scoped persistence
- Command execution during interactive sessions
- Credential harvesting or environment hijacking

**Key Insight:**
Highly dependent on user activity; stealth depends on blending with user configuration.

---

### 4. Event-Triggered Execution
**Examples:** network hooks, PAM, environment hooks  
**Behavior:** Executes when specific system events occur  

**Attacker Use:**
- Triggering execution only under certain conditions
- Reducing noise and detection footprint
- Maintaining persistence tied to system activity

**Key Insight:**
Often overlooked by analysts; high value due to conditional execution.

---

### 5. Execution Flow Hijacking
**Examples:** LD_PRELOAD, dynamic linker abuse, capabilities  
**Behavior:** Alters how binaries execute rather than scheduling execution  

**Attacker Use:**
- Injecting code into trusted processes
- Preloading malicious libraries
- Hijacking execution paths

**Key Insight:**
High stealth. Execution occurs inside legitimate processes.

---

### 6. Platform-Specific Persistence
**Examples:** containers, container runtimes  
**Behavior:** Persistence tied to container lifecycle or orchestration  

**Attacker Use:**
- Escaping traditional host-based detection
- Embedding persistence in infrastructure-as-code
- Leveraging misconfigured runtime privileges

**Key Insight:**
Increasingly relevant in modern environments; often missed in host-only analysis.

---

## Core Analytical Dimensions

Every Tenax finding is evaluated across the following dimensions:

### 1. Execution Context
- Root vs user
- Interactive vs non-interactive
- Service vs ephemeral process

### 2. Trigger Reliability
- Guaranteed (boot/systemd)
- Conditional (network hooks)
- Opportunistic (shell profiles)

### 3. Visibility
- High visibility (cron entries)
- Moderate (systemd units)
- Low (LD_PRELOAD, PAM)

### 4. Survivability
- Survives reboot?
- Survives account changes?
- Requires external infrastructure?

---

## Scoring Philosophy

Tenax scoring is not based on static signatures.

Instead, it evaluates:
- **Behavioral intent**
- **Execution semantics**
- **Deviation from baseline expectations**

### High Scores Indicate:
- Execution from suspicious paths (`/tmp`, `/dev/shm`)
- Network + execution chaining (e.g., `curl | bash`)
- Privileged execution contexts
- Execution flow manipulation

### Lower Scores Indicate:
- Potentially suspicious but common administrative patterns
- Single weak signals without execution guarantees

---

## Analyst-Centric Design

Tenax is not designed to replace analyst judgment.

It is designed to:
- **Reduce triage time**
- **Highlight high-probability persistence**
- **Provide contextual evidence**

Each finding includes:
- Source module
- Reasoning
- Execution preview
- Severity score

---

## Key Principle

> **Persistence is not where code lives.  
It is where and how code runs.**

Understanding this distinction is what separates:
- enumeration
- from analysis

Tenax is built to bridge that gap.
