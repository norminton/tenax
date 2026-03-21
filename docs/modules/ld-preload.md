# LD_PRELOAD and Dynamic Linker Hijacking Persistence

## Overview

`LD_PRELOAD` and related dynamic linker mechanisms are among the most powerful and least understood persistence surfaces in Linux. Unlike cron, systemd, or shell profiles, this category does not primarily rely on scheduling or visible startup orchestration. Instead, it alters **how trusted programs load and execute code**.

At a high level, dynamic linker hijacking works by forcing a process to load an attacker-controlled shared object (`.so`) before it loads the libraries it would normally use. In Linux environments that use the GNU dynamic linker, this can be influenced through mechanisms such as environment variables like `LD_PRELOAD`, as well as configuration surfaces including `/etc/ld.so.preload`. MITRE ATT&CK classifies this behavior under **T1574.006 – Hijack Execution Flow: Dynamic Linker Hijacking**. 

> **LD_PRELOAD persistence is dangerous because the attacker does not need to create an obvious recurring task. They can cause legitimate processes to execute attacker-controlled code as part of their normal startup path.**

---

## Why Attackers Use LD_PRELOAD for Persistence

Attackers use dynamic linker hijacking because it provides several strategic advantages:

- Execution inside legitimate processes  
- Reduced dependence on obvious persistence surfaces such as cron or services  
- Stealth through process masquerade  
- The ability to intercept function calls in user space  
- Frequent execution opportunities if widely used binaries are affected  
- Potential privilege implications when linked to privileged execution contexts  

Traditional persistence mechanisms answer the question, **“When will my code run?”**  
Dynamic linker hijacking answers a different question: **“What trusted program can I force to run my code for me?”**

This distinction is analytically important. Cron, systemd, and shell profiles are visible because they define execution. `LD_PRELOAD`-style abuse is stealthy because it **piggybacks on execution that already looks legitimate**.

---

## Execution Semantics

To understand why this mechanism matters, an analyst must understand how dynamically linked Linux binaries start.

When a dynamically linked ELF binary is executed, the kernel transfers control to the runtime linker/loader. That loader resolves shared library dependencies and maps the required libraries into process memory before normal application execution proceeds. The Linux `ld.so` documentation explicitly describes preloading behavior and the role of `LD_PRELOAD`, while also documenting configuration files such as `/etc/ld.so.preload`.  

### Core Concept

If an attacker can cause the loader to map a malicious shared object before legitimate ones, that attacker-controlled code can:

- override expected functions
- intercept API calls
- alter program behavior
- execute malicious initialization routines when the library is loaded

### Key Mechanisms

Common loader-related surfaces include:

- `LD_PRELOAD`
- `/etc/ld.so.preload`
- `/etc/ld.so.conf`
- `/etc/ld.so.conf.d/`

Among these, `/etc/ld.so.preload` is especially important because it can impose system-wide preloading behavior for dynamically linked programs. The loader documentation also notes that `LD_PRELOAD` affects preloading behavior, though environment-based behavior can be constrained in secure-execution contexts.  

### Execution Context

This mechanism is powerful because it can execute:

- whenever a targeted dynamically linked program starts
- in the security context of that process
- without requiring a new visible scheduler, timer, or service

That means the attacker’s code may run:

- when users launch common utilities
- when administrative tools execute
- when daemons start
- when login-related binaries are invoked

---

## Privilege Requirements

The privilege model depends on how the attacker establishes the hijack.

### User-Level Abuse

A user-level attacker may leverage environment-based injection in their own shell or startup files, for example by exporting `LD_PRELOAD`. This does not require root, but it typically affects only processes launched in that user’s environment.

### System-Level Abuse

Root-level attackers can modify:

- `/etc/ld.so.preload`
- system-wide environment hooks
- loader configuration files

This is far more severe because it can influence process execution across the system, depending on the exact binary, execution mode, and secure-execution constraints documented by the loader.  

---

## Why This Mechanism Is So Powerful

Most persistence mechanisms are externally visible because they create a new trigger.

Examples:

- cron creates a scheduled trigger  
- systemd creates a service trigger  
- shell profiles create a shell-start trigger  

Dynamic linker hijacking is different. It **injects malicious behavior into existing trusted execution**.

That gives attackers three major benefits:

### 1. Stealth

The process name often remains legitimate.  
The analyst may see `sshd`, `sudo`, or another normal binary, while the malicious behavior actually originates from an attacker-controlled shared object.

### 2. Frequency

If the attacker hijacks a widely used execution path, their code can run repeatedly without setting up repeated jobs.

### 3. Functional Interception

This mechanism is not limited to “run a shell script.”  
A malicious shared object can intercept user-space functions and alter behavior at a very granular level.

---

## Common Attacker Tradecraft

### 1. System-Wide Persistence via `/etc/ld.so.preload` (High Confidence Backdoor)

Example:

```
echo "/tmp/libaudit.so" > /etc/ld.so.preload
```

What this does:
- Forces the dynamic linker to load `/tmp/libaudit.so` into **every dynamically linked binary**
- Executes attacker-controlled code whenever a program starts
- Applies system-wide (subject to loader behavior and execution context)

Why attackers use this:
- No scheduler required (cron/systemd not needed)
- Executes frequently and naturally
- Blends into legitimate process execution
- Extremely persistent unless explicitly removed

Real-world implication:
- Any binary like `ls`, `sudo`, `ssh`, etc. may load the malicious library
- The attacker gains **continuous execution opportunities**

---

### 2. User-Level Persistence via `LD_PRELOAD` + Shell Profile

Example:

```
echo 'export LD_PRELOAD=/tmp/libcache.so' >> ~/.bashrc
```

What this does:
- Injects a malicious shared object into **every new shell session**
- Executes whenever the user opens a terminal or logs in

Why attackers use this:
- No root required
- Tied to user behavior (harder to baseline)
- Often overlooked during triage

Tradecraft pattern:
- Combine with shell profiles (`.bashrc`, `.profile`)
- Use stealthy library names (`libcache.so`, `libutil.so`)

---

### 3. Credential Interception via Function Hooking (Real Tradecraft)

Example concept:

A malicious `.so` overrides a function like:

```
int pam_authenticate(...)
```

or

```
int execve(...)
```

What this enables:
- Capture credentials during authentication
- Log commands executed by users
- Intercept sensitive operations

Example behavior:
- User runs `sudo`
- Malicious library intercepts authentication call
- Password is logged to `/tmp/.log`

Why attackers use this:
- Stealthy credential harvesting
- No need for keylogging tools
- Runs inside trusted processes

---

### 4. Privilege Escalation Assistance via LD_PRELOAD

Example:

```
export LD_PRELOAD=/tmp/libpriv.so
sudo some_binary
```

What this does:
- Attempts to inject malicious code into privileged execution paths
- Can be used to manipulate program behavior during escalation

Important note:
- Secure execution contexts may restrict LD_PRELOAD usage
- Attackers may instead target misconfigured or custom binaries

---

### 5. Backdooring Administrative Tools

Example:

```
echo "/tmp/libsshwrap.so" > /etc/ld.so.preload
```

Malicious behavior inside `.so`:
- Hooks SSH-related functions
- Logs remote connections
- Captures credentials or commands

Why this is dangerous:
- Affects administrators directly
- Blends into normal admin workflows
- High-value data collection

---

### 6. Blending with Legitimate Library Names

Example:

```
/tmp/libcrypto.so
/tmp/libpam.so
/tmp/libaudit.so
```

Why attackers use this:
- Exploits analyst assumptions
- Makes quick triage harder
- Mimics legitimate system libraries

Key insight:
> The name is not the indicator — the **path and origin** are.

---

### 7. Persistence with Minimal Disk Footprint

Example chain:

```
echo "/dev/shm/.lib.so" > /etc/ld.so.preload
```

Why attackers use this:
- `/dev/shm` is memory-backed (often ephemeral)
- Reduces forensic artifacts on disk
- Faster cleanup if discovered

---

### 8. Chained Persistence Mechanisms

Example:

```
echo 'export LD_PRELOAD=/tmp/lib.so' >> ~/.bashrc
```

Combined with:
- Cron fallback
- Systemd fallback

Why attackers do this:
- Redundancy
- Ensures persistence survives partial cleanup
- Forces analyst to remove multiple footholds


---

## What Normal Looks Like

Legitimate linker behavior generally involves:

- system libraries stored in standard library directories
- package-managed loader configuration
- no references to user-writable temporary paths
- no unexplained `LD_PRELOAD` exports in user startup files

Typical trusted library locations include system-managed library paths, not ad hoc user-writable staging areas.

Normal systems may legitimately use:
- `/etc/ld.so.conf`
- `/etc/ld.so.conf.d/`
- package-managed shared objects
  
These files are used to define shared library search paths and are part of normal dynamic linker behavior.

By contrast, `/etc/ld.so.preload` is often **absent by default** and may only appear when software or an administrator explicitly creates it.

This distinction is analytically important:

- The presence of `ld.so.conf` and `ld.so.conf.d/` is normal
- The presence of `ld.so.preload` is more unusual and often warrants closer investigation

> The absence of `/etc/ld.so.preload` is not evidence that dynamic linker abuse is impossible.  
> It only means that this specific preload mechanism is not currently present as a file.

However, those entries should generally:
- point to expected directories
- support installed software
- align with package inventory and system role

---

## What Malicious Use Looks Like

### High-Signal Indicators

- `LD_PRELOAD` set in startup files or environment hooks unexpectedly
- `/etc/ld.so.preload` present and pointing to non-standard paths
- shared objects loaded from:
  - `/tmp`
  - `/var/tmp`
  - `/dev/shm`
  - user home directories
- recently created `.so` files without package ownership
- suspicious shared object names mimicking trusted libraries
- correlation between library loading and anomalous process behavior

MITRE’s detection guidance for dynamic linker hijacking specifically highlights monitoring for unexpected `LD_PRELOAD` definitions, suspicious `.so` creation in user directories, and anomalous process execution associated with those modifications. 

### Medium-Signal Indicators

- unusual loader config changes
- hidden or newly added files in `ld.so.conf.d`
- user-scoped environment injection tied to login shells
- package-inconsistent libraries in local directories

### Low-Signal Indicators

- custom software development environments
- specialized instrumentation/debugging setups
- legitimate preload-based compatibility workarounds

These cases are less common on ordinary Linux endpoints and servers, but they do exist, so triage must remain evidence-driven.

---

## ATT&CK Mapping

- **T1574 – Hijack Execution Flow**
- **T1574.006 – Hijack Execution Flow: Dynamic Linker Hijacking**

This is one of the clearest ATT&CK mappings in Linux persistence analysis because the mechanism directly alters the loader’s behavior to introduce malicious code into trusted program execution.  

---

## Why Analysts Miss This Technique

Analysts often miss dynamic linker hijacking for four reasons:

### 1. It Does Not Look Like a Scheduler

There is no obvious recurring line like cron.

### 2. It Does Not Necessarily Create a New Process Name

The visible process may be legitimate.

### 3. The Artifact May Be Small

The persistence artifact may be a one-line file or environment export.

### 4. The Analyst May Focus Only on Execution Artifacts

If triage is limited to:
- services
- cron
- shell histories

then execution-flow hijacks can be missed entirely.

---

## Deep Analytical Guidance

### Key Question

> Is this system causing trusted binaries to load code from locations or sources they should never trust?

That is the right question.

The wrong question is:

> Is there a weird shared library somewhere?

A suspicious `.so` file alone is not enough.  
The real issue is whether the loader is being manipulated to **use** it.

---

### Focus Areas

#### 1. Control Surface

Determine how the preload is being established:

- shell startup file
- environment hook
- `/etc/ld.so.preload`
- loader config directory
- service environment override

#### 2. Scope

Ask:
- user-scoped or system-scoped?
- one process or many?
- interactive-only or broad background effect?

#### 3. Load Target

What binaries are likely to load the malicious object?

This matters because:
- loading into a rarely used binary is less severe operationally
- loading into authentication, privilege, or administrative paths is far more severe

#### 4. Library Provenance

Evaluate:
- path
- creation time
- owner
- permissions
- package ownership
- compilation metadata if available

#### 5. Behavioral Objective

Why is the attacker using this mechanism?

Possible objectives:
- persistence
- command execution
- credential capture
- result tampering
- stealth
- rootkit-like user-space hiding

---

## Triage Workflow

1. Inspect preload control surfaces:

```text
cat /etc/ld.so.preload
cat /etc/ld.so.conf
ls /etc/ld.so.conf.d/
```

2. Check for environment-based injection:

```text
grep -R "LD_PRELOAD" /etc/profile /etc/profile.d /etc/environment ~/.bashrc ~/.profile ~/.zshrc
```

3. Validate referenced shared object paths

4. Check metadata:

```text
stat /path/to/library.so
```

5. Determine package ownership if possible

6. Correlate with process execution, abnormal authentication behavior, or suspicious user-space anomalies

7. Preserve the shared object for offline analysis

---

## Evidence to Preserve

- `/etc/ld.so.preload`
- `/etc/ld.so.conf`
- `/etc/ld.so.conf.d/*`
- user startup files containing `LD_PRELOAD`
- referenced `.so` files
- file metadata (timestamps, ownership, permissions)
- package ownership information
- process execution telemetry
- logs showing authentication or process anomalies

If possible, also preserve:
- hashes of the library
- strings output
- symbol information
- static analysis notes

---

## False Positive Reduction

Because preload behavior can have legitimate uses, analysts must distinguish malicious abuse from specialized system behavior.

Reduce false positives by asking:

- Is this preload required by known software?
- Is the library package-managed?
- Is the path standard and expected?
- Does the host role justify unusual loader behavior?
- Is the library located in a non-persistent or user-writable directory?

A preload entry pointing to a package-managed compatibility library is very different from one pointing to `/tmp/libevil.so`.

---

## Why Tenax Checks This Surface

Tenax checks loader-related persistence because this mechanism has:

- high stealth value
- strong execution leverage
- broad tactical overlap with persistence, credential access, and defense evasion

It is also one of the easiest categories for less-experienced analysts to miss.

> A malicious cron job is visible because it schedules execution.  
> A malicious preload is dangerous because it disappears into trusted execution.

---

## Key Takeaway

Dynamic linker hijacking is not just a persistence mechanism. It is an **execution trust subversion mechanism**.

The attacker is not merely arranging for their code to run later.

> They are redefining what a legitimate program means when it runs.
