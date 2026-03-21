# False Positives

## Overview

False positives are unavoidable in Linux persistence analysis.

This is not because the analyst is careless, and it is not because the detection logic is broken. It is because many Linux persistence surfaces are also legitimate administrative surfaces.

The same mechanisms attackers use for persistence are often used by:

- system administrators
- package maintainers
- desktop environments
- configuration management systems
- developers
- cloud-init and bootstrap tooling
- enterprise authentication systems
- container platforms

This creates a central challenge:

> **The analyst is not just asking whether a mechanism exists. The analyst is asking whether its use is malicious, unnecessary, unauthorized, or inconsistent with the system’s purpose.**

Tenax is designed to prioritize suspicious findings, but no persistence tool can fully eliminate false positives without understanding:

- system role
- software inventory
- administrative intent
- business context
- timeline
- operator behavior

This document explains how to reduce false positives without becoming overly dismissive of real attacker tradecraft.

---

## Core Principle

A suspicious persistence artifact is not automatically malware.

Likewise, an administrative-looking artifact is not automatically benign.

The right mindset is:

> **Suspicious until explained. Benign only when behavior, provenance, timing, and context support that conclusion.**

This is especially important on Linux because attackers deliberately hide inside normal administration patterns.

Examples:

- a cron job may be a legitimate backup task  
- a systemd unit may be a package-managed service  
- a `.desktop` autostart entry may belong to a real desktop component  
- a PATH modification may be legitimate for developers  
- a PAM module may be part of enterprise authentication  
- a Docker container may be expected infrastructure  

The analyst’s job is not to react to existence alone.  
The analyst’s job is to understand **purpose and consequence**.

---

## Why False Positives Are Common in Linux Persistence Analysis

False positives are common because Linux systems are highly configurable, and many persistence surfaces are dual-use by design.

### 1. Linux Encourages Scriptability

Legitimate systems often contain:

- shell wrappers
- local admin scripts
- custom service units
- environment modifications
- startup helpers
- network event scripts

These may look suspicious to a rule-based scanner but be entirely legitimate.

### 2. Host Roles Vary Dramatically

A finding that is suspicious on one host may be normal on another.

Examples:
- a desktop autostart entry on a GNOME workstation may be expected
- the same entry on a headless production server may be highly suspicious

### 3. Package-Managed Software Can Look Strange

Some legitimate software installs:

- custom systemd units
- startup scripts
- environment hooks
- helper daemons
- service wrappers
- capabilities on binaries

Without package validation, these can appear malicious.

### 4. Administrators Often Use the Same Mechanisms as Attackers

Legitimate admins also use:

- cron
- systemd
- `/usr/local/bin`
- shell profiles
- NetworkManager hooks
- Docker restart policies

This means the mechanism is rarely the conclusion by itself.

---

## High-Level False Positive Reduction Strategy

The most effective false positive reduction process is:

1. **Confirm the mechanism**
2. **Understand what it executes**
3. **Validate provenance**
4. **Evaluate whether the behavior fits the host**
5. **Correlate with time and activity**
6. **Decide whether the finding is benign, suspicious, or malicious**

If you skip provenance and context, you will over-alert.  
If you skip behavioral review, you will miss real persistence.

---

## The Five Questions Every Analyst Should Ask

For any Tenax finding, ask these five questions.

### 1. What Exactly Executes?

Do not stop at the config line.

A cron entry, systemd unit, PAM config line, or autostart file is often just the trigger.

Ask:
- What binary, script, or library actually runs?
- Is the path trusted?
- Is the target file present?
- Is the target file package-managed?

### 2. Is This Expected for This Host Role?

Ask:
- Is this a workstation, server, container host, or build box?
- Is this a desktop environment?
- Is this a developer machine?
- Is this part of infrastructure automation?

A suspicious mechanism on one system may be completely normal on another.

### 3. Is the Timing Reasonable?

Ask:
- When was the file created?
- When was it modified?
- Does that align with software installation or patch windows?
- Does it align with suspicious activity?

Timing is often one of the strongest differentiators between:
- legitimate administrative change
- attacker-introduced persistence

### 4. Is the Artifact Package-Managed or Administrator-Owned?

Ask:
- Does the package manager know this file?
- Does the path align with legitimate software installation?
- Is the owner expected?
- Are the permissions normal?

A package-managed systemd unit in `/usr/lib/systemd/system/` is very different from a hidden helper in `/tmp`.

### 5. Does the Behavior Make Sense?

Even if the file is unusual, the critical question is behavioral:

- Does it fetch remote code?
- Does it execute from a temporary path?
- Does it alter privilege or trust?
- Does it intercept authentication?
- Does it recreate other persistence?

The more the answer is “yes,” the less likely this is a harmless administrative oddity.

---

## High-Signal vs Low-Signal Indicators

One of the biggest false-positive mistakes is treating all indicators as equal.

They are not equal.

### High-Signal Indicators

These are hard to explain away and should receive strong scrutiny:

- execution from `/tmp`, `/var/tmp`, `/dev/shm`
- `curl | bash`
- `wget | sh`
- `bash -c`, `sh -c`, `python -c`, `perl -e`
- `LD_PRELOAD` pointing to user-writable paths
- `ExecStart=` pointing to temporary or hidden paths
- `pam_exec.so` calling suspicious scripts
- SSH keys of unknown origin
- hidden binaries with dangerous capabilities
- container restart policies tied to suspicious commands
- startup scripts restoring other persistence

These are not always malicious, but they are strong signals.

### Medium-Signal Indicators

These require context:

- custom service names
- new cron jobs
- PATH changes
- desktop autostart entries
- environment hook modifications
- NetworkManager dispatcher scripts
- `NOPASSWD` sudoers rules
- user-level systemd services

These are common in both benign and malicious workflows.

### Low-Signal Indicators

These are often noise unless paired with stronger evidence:

- existence of a known persistence path
- normal package-managed services
- normal desktop components
- standard capabilities on common binaries
- legitimate cron maintenance jobs
- ordinary `/etc/profile` customizations

A low-signal artifact becomes more important when correlated with:
- suspicious timing
- suspicious payloads
- suspicious references
- suspicious ownership
- suspicious network activity

---

## Common False Positive Scenarios by Module

---

## Cron

Reference notes:

- [Cron Persistence](modules/cron.md)

### Frequent False Positives

- legitimate backup jobs
- maintenance scripts
- log rotation wrappers
- monitoring checks
- vendor-installed cron tasks

### How to Reduce Noise

Ask:
- Does the job run a trusted binary?
- Is the schedule reasonable?
- Does the command fit the system’s function?
- Is the script documented or package-managed?

### Stronger Suspicion

Escalate when cron references:
- temporary paths
- remote retrieval
- obfuscated shell execution
- hidden or newly created payloads

---

## Systemd

Reference notes:

- [Systemd Persistence](modules/systemd.md)

### Frequent False Positives

- package-installed services
- custom internal services
- local wrappers for line-of-business apps
- development/test services

### How to Reduce Noise

Ask:
- Is the unit package-managed?
- Does the `ExecStart=` path belong to known software?
- Does the service name match legitimate functionality?
- Is the unit expected for this host?

### Stronger Suspicion

Escalate when:
- `ExecStart=` references `/tmp`, `/dev/shm`, hidden user paths
- service name is suspiciously generic or masquerading
- service uses shell chaining or remote retrieval
- unit was created recently outside normal admin activity

---

## Shell Profiles

Reference notes:

- [Shell Profile Persistence](modules/shell-profiles.md)

### Frequent False Positives

- aliases
- PATH customizations
- prompt customizations
- developer environment variables
- shell framework modifications

### How to Reduce Noise

Ask:
- Is this configuration-only or execution-causing?
- Does it reference trusted tooling?
- Is this normal for the user’s workflow?
- Is it common across multiple developer systems?

### Stronger Suspicion

Escalate when:
- the line executes code
- the line fetches remote content
- the line references temp paths
- `LD_PRELOAD`, `PROMPT_COMMAND`, `BASH_ENV`, or command hijacking are involved

---

## SSH

Reference notes:

- [SSH Authorized Keys Persistence](modules/ssh.md)

### Frequent False Positives

- legitimate admin key rotation
- infrastructure automation keys
- backup/management keys
- CI/CD service keys

### How to Reduce Noise

Ask:
- Is the key inventoried?
- Does it belong to an expected user or automation system?
- Is the comment field meaningful?
- Do SSH logs support legitimate use?

### Stronger Suspicion

Escalate when:
- unknown keys appear in root accounts
- forced command options are used
- multiple unknown keys appear together
- file modification time aligns with suspicious activity

---

## Sudoers

Reference notes:

- [Sudoers Persistence and Privilege Abuse](modules/sudoers.md)

### Frequent False Positives

- legitimate admin delegation
- deployment tooling
- automation pipelines
- restricted operational workflows

### How to Reduce Noise

Ask:
- Is the rule aligned with actual job function?
- Is the user expected to have this level of privilege?
- Is the rule documented internally?

### Stronger Suspicion

Escalate when:
- `NOPASSWD` is paired with shell-capable binaries
- broad `ALL=(ALL)` grants appear unexpectedly
- new include files appear without operational explanation
- rules benefit newly created or suspicious accounts

---

## RC / Init

Reference notes:

- [RC / Init Persistence](modules/rc-init.md)

### Frequent False Positives

- old package compatibility scripts
- legacy local startup automation
- internal boot helpers
- migration leftovers from pre-systemd environments

### How to Reduce Noise

Ask:
- Is the host actually using this mechanism?
- Is the script package-managed?
- Does the script’s function match the host role?

### Stronger Suspicion

Escalate when:
- scripts launch from temporary paths
- scripts fetch remote content
- symlinks point to suspicious or hidden targets
- runlevel entries were recently modified

---

## Temporary Paths

Reference notes:

- [Temporary Path Abuse in Persistence](modules/tmp-paths.md)

### Frequent False Positives

- installer leftovers
- editor swap files
- application caches
- build artifacts
- transient logs

### How to Reduce Noise

Ask:
- Is the file actually executed?
- Is the file referenced by another mechanism?
- Is the file transient or long-lived?
- Is it owned by expected processes/users?

### Stronger Suspicion

Escalate when:
- the file is executable
- it is referenced by cron/systemd/PAM/etc.
- it is hidden and long-lived
- it contains loader abuse, shell chaining, or network retrieval

---

## LD_PRELOAD / Loader Hijack

Reference notes:

- [LD_PRELOAD and Dynamic Linker Hijacking Persistence](modules/ld-preload.md)

### Frequent False Positives

- compatibility libraries
- specialized instrumentation
- developer or testing environments
- package-managed loader configuration

### How to Reduce Noise

Ask:
- Is the preload mechanism actually active?
- Is the referenced library package-managed?
- Does the host role justify unusual loader behavior?

### Stronger Suspicion

Escalate when:
- `/etc/ld.so.preload` exists and points to suspicious paths
- `LD_PRELOAD` references `/tmp`, `/home`, or hidden user paths
- the library is not package-managed
- library naming appears masqueraded

---

## Autostart Hooks

Reference notes:

- [Autostart Hook Persistence](modules/autostart-hooks.md)

### Frequent False Positives

- legitimate desktop helper apps
- session restore components
- update agents
- vendor tray applications

### How to Reduce Noise

Ask:
- Is this a graphical desktop system?
- Does the `.desktop` file align with installed applications?
- Is the `Exec=` path package-managed and trusted?

### Stronger Suspicion

Escalate when:
- `Exec=` points to temporary or hidden paths
- the entry name masquerades as a system helper
- the file appears recently without related software installation
- the host should not have user-session autostart activity at all

---

## At Jobs

Reference notes:

- [At Job Persistence](modules/at-jobs.md)

### Frequent False Positives

- delayed maintenance tasks
- one-time admin jobs
- test execution
- user convenience scheduling

### How to Reduce Noise

Ask:
- Is the scheduled command legitimate?
- Does the timing align with maintenance windows?
- Is the job truly one-time, or is it re-queuing itself?

### Stronger Suspicion

Escalate when:
- the job runs from a temp path
- the job restores other persistence
- the job is scheduled far in the future after suspicious access
- the command uses remote retrieval or shell chaining

---

## Network Hooks

Reference notes:

- [Network Hook Persistence](modules/network-hooks.md)

### Frequent False Positives

- real interface management scripts
- DHCP hooks
- DNS adjustments
- monitoring or VPN support tooling

### How to Reduce Noise

Ask:
- Does this script actually perform a networking function?
- Is it package-managed or documented?
- Does it belong on this host?

### Stronger Suspicion

Escalate when:
- the script launches non-network payloads
- the script references temp paths
- the hook is used to restore cron/systemd/SSH persistence
- the script uses remote retrieval or hidden payloads

---

## Containers

Reference notes:

- [Container-Based Persistence](modules/containers.md)

### Frequent False Positives

- expected sidecars
- normal restart policies
- internal helper containers
- debug or transient containers
- CI/CD runners

### How to Reduce Noise

Ask:
- Does the container belong to expected infrastructure?
- Is the image trusted?
- Does the command align with the image purpose?
- Is the orchestration definition legitimate?

### Stronger Suspicion

Escalate when:
- restart policies keep suspicious commands alive
- containers fetch and execute remote payloads
- unknown services or sidecars appear
- minimal images are used only to run shell loops or callbacks
- Docker socket abuse is involved

---

## Environment Hooks

Reference notes:

- [Environment Hook Persistence](modules/environment-hooks.md)

### Frequent False Positives

- locale configuration
- proxies
- developer PATH adjustments
- language runtime customization
- package compatibility settings

### How to Reduce Noise

Ask:
- Does this variable merely configure, or does it redirect execution?
- Is the path trusted?
- Is this expected for the user or host role?

### Stronger Suspicion

Escalate when:
- `PATH` prepends unsafe directories
- `LD_PRELOAD`, `LD_LIBRARY_PATH`, `BASH_ENV`, or `PYTHONPATH` point to suspicious locations
- the value creates execution or hijack behavior
- the environment hook supports another persistence surface

---

## PAM

Reference notes:

- [PAM Persistence and Authentication Hooking](modules/pam.md)

### Frequent False Positives

- legitimate enterprise auth modules
- MFA integrations
- package-managed PAM customizations
- central authentication tooling

### How to Reduce Noise

Ask:
- Is the module package-managed?
- Is this expected in the organization’s auth architecture?
- Does the module or line alter trust in a meaningful way?

### Stronger Suspicion

Escalate when:
- custom modules appear
- `pam_exec.so` runs suspicious scripts
- modules reference temp paths
- auth stack order or control flags were altered unexpectedly
- auth behavior changed without legitimate rollout context

---

## Capabilities

Reference notes:

- [Linux Capabilities Persistence](modules/capabilities.md)

### Frequent False Positives

- standard capabilities on `ping` or other expected tools
- package-managed assignments
- security-hardening use cases

### How to Reduce Noise

Ask:
- Does the capability make sense for the binary?
- Is the binary package-managed?
- Is the path trusted?

### Stronger Suspicion

Escalate when:
- `cap_setuid`, `cap_setgid`, or similar dangerous capabilities appear on unusual binaries
- interpreters or hidden binaries have capabilities
- binaries in user-writable paths carry capabilities
- capabilities support another persistence or privilege path

---

## The Most Common Analyst Mistakes

### Mistake 1: Trusting Names Instead of Behavior

Attackers know that names influence triage.

Examples:
- `dbus-update`
- `network-helper`
- `backup-monitor`
- `system-update`

A plausible name is not evidence of legitimacy.

### Mistake 2: Treating Package Paths as Automatically Safe

Even trusted-looking paths can be abused if:
- files are replaced
- package ownership is absent
- local files masquerade inside expected trees

### Mistake 3: Overreacting to Any Customization

Linux systems often have real local customization. Not every shell alias, cron job, or unit file is malicious.

### Mistake 4: Dismissing Strange Things Because They “Look Like Admin Stuff”

Attackers intentionally mimic admin patterns.  
A persistence mechanism that looks “boring” may be the most important finding on the host.

### Mistake 5: Ignoring Timing

Recent modification times often separate:
- long-standing legitimate configuration
from
- attacker-introduced persistence

### Mistake 6: Failing to Validate Scope

A weird autostart entry on a headless server is more suspicious than one on a GNOME workstation.  
A weird PAM module on an enterprise bastion host is more suspicious than on a custom auth appliance.  
Scope matters.

---

## Practical False Positive Reduction Workflow

For each finding:

### Step 1: Preserve
- record path
- capture contents
- hash file
- capture metadata

### Step 2: Inspect Execution
- what executes?
- when?
- under what privileges?
- from what path?

### Step 3: Validate Provenance
- package-managed?
- expected owner?
- expected path?
- known software?

### Step 4: Validate Context
- host role?
- desktop vs server?
- developer vs production?
- orchestration environment?

### Step 5: Correlate
- auth logs
- process history
- network telemetry
- file creation times
- shell history
- package install history

### Step 6: Decide Classification

A useful internal classification model is:

- **Benign**  
  behavior, provenance, and context align

- **Suspicious / Needs Validation**  
  not explainable yet, but not confirmed malicious

- **Malicious / Unauthorized**  
  behavior, provenance, or correlation strongly supports attacker use

This helps avoid binary thinking too early.

---

## When to Trust Tenax More Aggressively

Tenax findings should be treated with especially high confidence when multiple signals combine.

Examples:
- systemd `ExecStart=` pointing to `/tmp`
- autostart `Exec=` pointing to hidden user path
- PAM `pam_exec.so` running a temp script
- container with restart policy and `curl | bash`
- hidden binary with `cap_setuid`
- cron entry restoring another persistence surface

> **The more a finding combines trigger + unsafe path + suspicious behavior, the lower the chance it is a benign false positive.**

---

## Final Principle

False positive reduction is not about explaining away suspicious findings.  
It is about separating:

- expected administration
from
- attacker-controlled persistence

The analyst must resist both extremes:

- seeing malware in everything
- trusting anything that looks administrative

The correct approach is disciplined, contextual, and evidence-driven.

> **A good analyst does not ask “Could this be normal?” in isolation.  
> A good analyst asks “Is this normal here, for this system, in this timeline, with this behavior?”**
