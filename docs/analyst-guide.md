# Analyst Guide

## Overview

Linux persistence analysis is deep, time-consuming, and highly contextual.

Unlike many Windows environments, where analysts may already have mature expectations for startup items, services, and registry-backed persistence, Linux persistence often spans:

- legacy initialization mechanisms
- modern service managers
- user-scoped startup behavior
- authentication hooks
- loader manipulation
- desktop session startup
- container runtimes
- privilege-persistence mechanisms
- execution hijacking
- payload staging locations

This means Linux persistence analysis is rarely a “quick check.”

A real persistence investigation often requires:

- broad enumeration
- careful prioritization
- file and configuration review
- behavioral analysis
- validation of execution paths
- ownership and provenance analysis
- package-management comparison
- timeline reconstruction
- understanding of how multiple persistence mechanisms may chain together

> **Persistence analysis is not just about finding suspicious files. It is about understanding how the system is being made to execute attacker-controlled logic over time.**

Because of that, analysts should not start with broad manual review unless they already have a very specific reason to do so.

## Start with Tenax Analyze Mode

Tenax is designed to help solve the biggest problem in Linux persistence analysis:

> **There are too many places to look, and not enough analyst time to treat every location equally.**

For that reason, the first step in most investigations should be:

```text
tenax analyze
```

or, if not installed as a console script:

```text
python main.py analyze
```

If the host permits it and the investigation allows it, root-level execution is preferred:

```text
sudo python main.py analyze
```

This matters because many high-value persistence surfaces are:

- privileged
- partially unreadable to non-root users
- stored in restricted locations
- only fully visible with elevated access

### Why Start Here

The `analyze` mode is intended to:

- rapidly identify high-probability persistence artifacts
- score suspicious findings
- prioritize analyst attention
- reduce time lost on low-signal locations
- expose the most dangerous execution paths first

Analysts should always review Tenax findings **before** attempting full manual review of every supported module.

> **Tenax is not a replacement for manual analysis. It is a prioritization engine that tells the analyst where to spend time first.**

---

## Critical Principle: One Persistence Mechanism Does Not Mean Only One Persistence Mechanism

One of the most dangerous assumptions in incident response is:

> “We found the persistence.”

That assumption is often wrong.

Attackers, especially those with elevated privileges, frequently establish:

- multiple persistence mechanisms
- persistence plus privilege re-entry
- persistence plus credential access
- persistence plus recovery logic
- one primary trigger and several fallback triggers

This is particularly common when the attacker had:

- root access
- access to administrative tooling
- time on the host
- repeat interactive access
- access to infrastructure or orchestration layers

### What This Means for Analysts

If you find one persistence mechanism, you should assume at least one of the following is still possible:

- there is another persistence mechanism elsewhere
- there is a recovery mechanism designed to recreate the one you found
- there is a privilege-escalation mechanism paired with it
- there is an access-preservation mechanism such as SSH key abuse
- the discovered mechanism is only the trigger, while the real payload lives elsewhere

For example:

- a systemd unit may launch a payload from `/tmp`
- that payload may restore a cron job
- the cron job may relaunch an SSH backdoor
- the SSH backdoor may provide access to an account with sudoers abuse
- the sudo path may restore a deleted PAM or loader hijack

> **Do not stop at the first finding. The goal is not to identify one malicious artifact. The goal is to understand the attacker’s persistence architecture on the host.**

---

## Recommended Investigation Workflow

A strong persistence investigation should follow a structured order.

### Phase 1: Run Tenax Analyze Mode

Start with:

```text
tenax analyze
```

or:

```text
sudo python main.py analyze
```

Review findings in priority order.

Focus first on:

- HIGH severity
- strong execution triggers
- suspicious temporary path execution
- inline shell execution
- remote retrieval and execution
- authentication or privilege control
- stealth mechanisms such as loader hijacking or PAM abuse

### Phase 2: Run Tenax Collect Mode

After initial prioritization, run:

```text
tenax collect
```

or:

```text
sudo python main.py collect --hash
```

Use collection mode to:

- enumerate all known persistence-related locations
- preserve paths for manual review
- compare suspicious findings against broader context
- hash and document relevant artifacts

### Phase 3: Expand from Trigger to Payload

For each finding, determine:

1. **What triggers execution?**
2. **What file, binary, script, or library actually runs?**
3. **What user or service context executes it?**
4. **What other mechanisms does it reference or restore?**

Analysts should always move from:
- trigger
to
- payload
to
- supporting infrastructure
to
- related persistence layers

### Phase 4: Validate, Confirm, and Scope

Once a suspicious artifact is identified, determine:

- Is it malicious?
- Is it merely suspicious but benign?
- Is it package-managed?
- Is it expected for the host role?
- Is it referenced elsewhere?
- Did it execute?
- Did it restore or stage something else?

### Phase 5: Continue Until Persistence Architecture Is Understood

Do not end the investigation when one malicious file is found.

End only when you can confidently explain:

- how the attacker returns
- how the attacker executes
- how the attacker escalates
- how the attacker survives cleanup
- what artifacts must be removed to fully evict them

---

## Module-by-Module Investigation Guide

Below is the recommended investigation flow for each Tenax module.

---

## 1. Cron

Reference notes:

- [Cron Persistence](modules/cron.md)

### Why It Matters

Cron provides scheduled execution and is one of the most common Linux persistence mechanisms.

### What to Review

- `/etc/crontab`
- `/etc/cron.d/`
- `/var/spool/cron/`
- `/etc/cron.hourly/`
- `/etc/cron.daily/`
- `/etc/cron.weekly/`
- `/etc/cron.monthly/`

### What to Look For

- execution from `/tmp`, `/var/tmp`, `/dev/shm`
- use of `curl`, `wget`, `bash -c`, `sh -c`
- obfuscated commands
- unexpected user context
- jobs added recently
- jobs with no operational reason to exist

### How to Confirm

Ask:
- What command is actually being run?
- Does the referenced script exist?
- Is the path trusted?
- Does the schedule make sense for the host role?

### Analyst Action

If suspicious:
1. inspect the cron entry
2. inspect the referenced payload
3. review file metadata
4. review command history if available
5. determine whether the job restores or launches other persistence

---

## 2. Systemd

Reference notes:

- [Systemd Persistence](modules/systemd.md)

### Why It Matters

Systemd is one of the highest-value persistence surfaces on Linux because it provides reliable, often privileged execution.

### What to Review

- `/etc/systemd/system/`
- `/lib/systemd/system/`
- `/usr/lib/systemd/system/`
- user units under `~/.config/systemd/user/`

### What to Look For

- suspicious `ExecStart=`
- execution from user-writable or temporary paths
- inline shell execution
- suspicious unit names
- new units inconsistent with installed software
- unusual restart policies

### How to Confirm

Ask:
- Is this unit package-managed?
- Does the unit name match real software?
- Does the `ExecStart` path make sense?
- Does the host role justify the unit?

### Analyst Action

1. inspect the unit file
2. inspect the referenced binary/script
3. review `journalctl` for the unit if available
4. validate package ownership
5. determine whether the unit launches or restores other persistence

---

## 3. Shell Profiles

Reference notes:

- [Shell Profile Persistence](modules/shell-profiles.md)

### Why It Matters

Shell profiles turn user activity into the trigger for attacker execution.

### What to Review

- `~/.bashrc`
- `~/.bash_profile`
- `~/.profile`
- `~/.zshrc`
- `/etc/profile`
- `/etc/bash.bashrc`
- `/etc/profile.d/`

### What to Look For

- `curl`, `wget`, `bash -c`
- execution from `/tmp`, `/dev/shm`, `/var/tmp`
- `LD_PRELOAD`
- `PROMPT_COMMAND`
- `BASH_ENV`
- command hijacking
- aliases or functions replacing trusted commands

### How to Confirm

Ask:
- Is this a configuration line or an execution line?
- Does this belong to normal user customization?
- Does the line cause code to run every time a shell starts?

### Analyst Action

1. isolate suspicious lines
2. identify referenced payloads
3. determine scope: user-only or system-wide
4. check whether other users have similar modifications
5. correlate with login and shell activity

---

## 4. SSH

Reference notes:

- [SSH Authorized Keys Persistence](modules/ssh.md)

### Why It Matters

SSH persistence preserves access rather than directly scheduling execution.

### What to Review

- `~/.ssh/authorized_keys`
- `/root/.ssh/authorized_keys`
- related SSH configuration if needed

### What to Look For

- unknown keys
- new keys in root account
- forced command options
- suspicious comments
- unusual restrictions or source constraints
- recent modification times

### How to Confirm

Ask:
- Does this key belong to a real user or automation workflow?
- Was it approved?
- Is the key expected on this host?

### Analyst Action

1. inventory all keys
2. validate with system owners if possible
3. correlate with SSH logs
4. determine whether key access was used operationally
5. check for linked privilege persistence

---

## 5. Sudoers

Reference notes:

- [Sudoers Persistence and Privilege Abuse](modules/sudoers.md)

### Why It Matters

Sudoers abuse is a privilege-persistence mechanism. It may not trigger execution on its own, but it can guarantee future elevated access.

### What to Review

- `/etc/sudoers`
- `/etc/sudoers.d/`

### What to Look For

- `NOPASSWD`
- broad `ALL=(ALL)` or `ALL=(ALL:ALL)` rules
- shell access via `/bin/bash`, `/bin/sh`
- shell-escape-capable binaries
- new include files
- recent modifications

### How to Confirm

Ask:
- Is this rule operationally justified?
- Does the user need this scope?
- Does the rule create a direct escalation path?

### Analyst Action

1. inspect full rule context
2. determine who benefits from the rule
3. validate legitimacy with policy/baseline
4. correlate with account activity
5. investigate linked persistence or account manipulation

---

## 6. RC / Init

Reference notes:

- [RC / Init Persistence](modules/rc-init.md)

### Why It Matters

These are boot-time execution surfaces that may still be active on many systems, especially legacy or mixed-init environments.

### What to Review

- `/etc/rc.local`
- `/etc/init.d/`
- `/etc/rc*.d/`

### What to Look For

- suspicious scripts
- startup execution from temporary paths
- suspicious symlink targets
- inline remote retrieval
- hidden payloads launched at boot

### How to Confirm

Ask:
- Is the host actually using these mechanisms?
- Does this script belong to a real package or admin workflow?
- Does it launch something that should never run at boot?

### Analyst Action

1. inspect script bodies
2. inspect referenced targets
3. validate runlevel links
4. review file metadata and ownership
5. determine whether boot-time execution restores other footholds

---

## 7. Temporary Paths

Reference notes:

- [Temporary Path Abuse in Persistence](modules/tmp-paths.md)

### Why It Matters

Temporary paths are not persistence mechanisms themselves, but they are frequently where the actual payloads live.

### What to Review

- `/tmp`
- `/var/tmp`
- `/dev/shm`

### What to Look For

- executable files
- hidden files with suspicious names
- `.so` files
- scripts referenced by persistence mechanisms
- files recreated after deletion
- file names masquerading as legitimate helpers

### How to Confirm

Ask:
- Is this file being executed by something else?
- Is it referenced from cron, systemd, PAM, or autostart?
- Does it contain remote execution or staging logic?

### Analyst Action

1. inspect contents
2. inspect metadata
3. hash and preserve the artifact
4. search for references elsewhere on the host
5. determine whether it is staging, payload, or restoration logic

---

## 8. LD_PRELOAD / Loader Hijack

Reference notes:

- [LD_PRELOAD and Dynamic Linker Hijacking Persistence](modules/ld-preload.md)

### Why It Matters

This is one of the stealthiest execution-hijacking mechanisms on Linux.

### What to Review

- `/etc/ld.so.preload`
- `/etc/ld.so.conf`
- `/etc/ld.so.conf.d/`
- environment-based preload definitions

### What to Look For

- unexpected `LD_PRELOAD`
- suspicious `.so` paths
- references to `/tmp`, `/var/tmp`, `/dev/shm`
- user-writable library locations
- newly added loader-related config

### How to Confirm

Ask:
- Is the library actually expected on this system?
- Is the host using a compatible loader?
- Is the path trusted?
- Is this package-managed?

### Analyst Action

1. inspect the control surface that defines the preload
2. preserve the referenced `.so`
3. hash and analyze the library
4. determine whether it intercepts execution or authentication
5. check for linked environment hook persistence

---

## 9. Autostart Hooks

Reference notes:

- [Autostart Hook Persistence](modules/autostart-hooks.md)

### Why It Matters

Autostart hooks are true user-session persistence mechanisms, especially valuable on workstations and admin desktops.

### What to Review

- `/etc/xdg/autostart/`
- `~/.config/autostart/`
- `~/.config/systemd/user/`
- related session environment hooks if involved

### What to Look For

- suspicious `.desktop` files
- fake updater/helper names
- suspicious `Exec=`
- execution from hidden or temporary paths
- newly created session services

### How to Confirm

Ask:
- Is this a real desktop component?
- Is the `Exec=` path trusted?
- Is this host actually using a desktop session where this matters?

### Analyst Action

1. inspect the autostart definition
2. inspect the referenced payload
3. validate package ownership if applicable
4. correlate with login-time process execution
5. determine whether it launches other persistence or C2

---

## 10. At Jobs

Reference notes:

- [At Job Persistence](modules/at-jobs.md)

### Why It Matters

`at` is a delayed-execution mechanism that can simulate persistence through chaining or restoration.

### What to Review

- `atq`
- `at -c <job_id>`
- spool locations if accessible

### What to Look For

- delayed execution far in the future
- jobs restoring other persistence
- jobs executing temporary payloads
- jobs with remote retrieval
- jobs re-queuing themselves

### How to Confirm

Ask:
- Is this a one-time admin task or a delayed intrusion action?
- Does the job recreate itself or other persistence?
- Does the timing align with suspicious activity?

### Analyst Action

1. list queued jobs
2. inspect full job contents
3. preserve the scheduled command and referenced payload
4. determine whether the job is persistence-adjacent or restoration-focused
5. correlate with user and shell history

---

## 11. Network Hooks

Reference notes:

- [Network Hook Persistence](modules/network-hooks.md)

### Why It Matters

These mechanisms trigger execution when connectivity changes, making them ideal event-driven persistence on mobile or dynamic systems.

### What to Review

- `/etc/NetworkManager/dispatcher.d/`
- DHCP hook paths
- `/etc/network/if-up.d/`
- `/etc/network/if-down.d/`
- other distro-relevant network hook locations

### What to Look For

- execution from temporary paths
- scripts unrelated to network configuration
- remote retrieval
- scripts restoring other persistence
- suspicious hook names

### How to Confirm

Ask:
- Does this script perform legitimate networking tasks?
- Does it simply use network state as a trigger?
- Is its behavior expected for the host?

### Analyst Action

1. inspect all hook scripts
2. validate payload references
3. correlate with connection events
4. review file provenance
5. determine whether execution occurs on reconnect, DHCP, or interface-up events

---

## 12. Containers

Reference notes:

- [Container-Based Persistence](modules/containers.md)

### Why It Matters

Container persistence may exist entirely outside traditional host persistence surfaces.

### What to Review

- running containers
- stopped containers
- restart policies
- compose files
- runtime configs
- orchestration manifests if applicable

### What to Look For

- suspicious restart policies
- inline shell loops
- remote retrieval
- hidden helper containers
- unusual images
- malicious sidecars or DaemonSets
- Docker socket abuse

### How to Confirm

Ask:
- Is this container expected in the environment?
- Does its command align with the image purpose?
- Is orchestration recreating it automatically?

### Analyst Action

1. enumerate runtime objects
2. inspect entrypoints and commands
3. inspect restart policies
4. inspect compose or orchestration configs
5. determine whether persistence exists in runtime state, image, or config definition

---

## 13. Environment Hooks

Reference notes:

- [Environment Hook Persistence](modules/environment-hooks.md)

### Why It Matters

Environment hooks alter execution conditions rather than directly scheduling execution.

### What to Review

- `/etc/environment`
- `/etc/environment.d/`
- `/etc/security/pam_env.conf`
- `~/.pam_environment`
- `~/.config/environment.d/`

### What to Look For

- `LD_PRELOAD`
- `LD_LIBRARY_PATH`
- `PATH=` prepending unsafe directories
- `PYTHONPATH`
- `BASH_ENV`
- `ENV=`
- `PROMPT_COMMAND`

### How to Confirm

Ask:
- Does this variable create execution, interception, or hijack behavior?
- Does the referenced path belong on this host?
- Is the variable supporting another persistence mechanism?

### Analyst Action

1. isolate suspicious environment definitions
2. inspect referenced files or directories
3. determine scope (user vs system)
4. search for chaining into shell profiles, loaders, or path hijack
5. confirm whether execution is actually affected on the host

---

## 14. PAM

Reference notes:

- [PAM Persistence and Authentication Hooking](modules/pam.md)

### Why It Matters

PAM is one of the highest-value persistence and credential access surfaces on Linux because it operates at the point of trust establishment.

### What to Review

- `/etc/pam.d/`
- `/etc/pam.conf`
- referenced modules
- `pam_exec.so` usage
- custom `.so` modules

### What to Look For

- unknown PAM modules
- references to temporary paths
- `pam_exec.so` invoking suspicious scripts
- reordered auth stacks
- suspicious control flags
- new service-specific modifications

### How to Confirm

Ask:
- Is this module legitimate and package-managed?
- Does this line alter authentication logic?
- Could this capture credentials or bypass auth?

### Analyst Action

1. inspect the exact PAM file modified
2. inspect all referenced modules or scripts
3. preserve suspicious `.so` files
4. validate package ownership and timestamps
5. correlate with auth logs and attacker access patterns

---

## 15. Capabilities

Reference notes:

- [Linux Capabilities Persistence](modules/capabilities.md)

### Why It Matters

Capabilities are privilege-persistence mechanisms stored in binary metadata, not traditional config files.

### What to Review

- output of `getcap -r / 2>/dev/null`
- suspicious binaries with capabilities
- high-risk capabilities such as `cap_setuid`

### What to Look For

- capability-enabled interpreters
- hidden binaries with capabilities
- binaries in user-writable paths
- suspicious assignments such as:
  - `cap_setuid`
  - `cap_setgid`
  - `cap_dac_read_search`
  - `cap_sys_admin`

### How to Confirm

Ask:
- Does this capability make sense for this binary?
- Is the binary package-managed?
- Is it in a trusted path?

### Analyst Action

1. enumerate capabilities
2. isolate high-risk assignments
3. preserve binaries
4. check hashes, metadata, and package ownership
5. determine whether capabilities are supporting another persistence chain

---

## How to Safely Confirm Whether Something Is Malicious

Finding something suspicious is not the same as proving it is malicious.

Analysts should avoid making a binary conclusion too early.

### Step 1: Preserve Before Altering

Before changing or deleting anything:

- record the path
- hash the file
- capture metadata
- preserve contents
- preserve related configuration
- record references from other locations

### Step 2: Inspect the Execution Logic

For a script or config, determine:

- what executes
- when it executes
- under which user
- whether it references a second-stage payload
- whether it restores other mechanisms

### Step 3: Validate Provenance

Ask:
- Is it package-managed?
- Does it belong to known software?
- Was it created recently?
- Is the owner expected?
- Does the path align with system role?

### Step 4: Review Behavior, Not Just Appearance

A benign-looking file name means nothing by itself.

Examples:
- `dbus-update`
- `backup-monitor`
- `network-helper`

These may be malicious or benign.

What matters is:
- execution path
- contents
- provenance
- references
- timing
- behavior

### Step 5: Correlate with Other Evidence

Strong confirmation often comes from correlation:

- creation time
- authentication logs
- shell history
- process execution
- network connections
- package manager history
- user activity timeline

### Step 6: Escalate to Deeper Analysis When Needed

If a file may be malicious but is not obviously so:

- perform static analysis
- inspect strings
- inspect imports
- run file-type checks
- isolate in a lab if safe and authorized
- review with malware analysis workflows

---

## How to Safely Research a Suspicious Artifact

When researching a suspicious script, binary, unit file, or module:

### For Scripts

Read it fully and answer:
- What triggers it?
- What commands does it run?
- Does it fetch remote content?
- Does it modify configs?
- Does it recreate persistence?

### For Binaries

Determine:
- file type
- hashes
- strings
- package ownership
- whether it is signed or expected
- whether it is referenced elsewhere

### For Shared Objects / PAM Modules / Loader Artifacts

Determine:
- where they are loaded from
- who references them
- whether they are package-managed
- whether they expose suspicious strings or symbols
- whether they are placed in nonstandard locations

### For Config Files

Determine:
- whether the line is normal for the system
- whether it creates execution
- whether it changes trust or privilege
- whether it points to something else you must inspect

> **Research should always move outward from the suspicious line to the real execution object, then outward again to every other mechanism that references it.**

---

## Recommended Confirmation Mindset

Analysts should avoid two bad habits:

### Bad Habit 1: Declaring Everything Malicious Too Early

Not every strange line is malware.

### Bad Habit 2: Declaring Everything Benign Because It Looks Administrative

Attackers intentionally use:
- admin-sounding names
- expected directories
- real interpreters
- trusted-looking wrappers

The right mindset is:

> **Suspicious until explained.  
> Benign only when context, provenance, and behavior support it.**

---

## Final Analyst Principles

### 1. Start with Tenax Analyze Mode

Use Tenax to prioritize effort.

### 2. Do Not Stop at One Finding

Assume layered persistence until proven otherwise.

### 3. Always Expand from Trigger to Payload

The line you find is often not the real payload.

### 4. Validate Provenance

Package ownership, metadata, and host role matter.

### 5. Preserve Before Removing

If you delete first, you may destroy the best evidence.

### 6. Think in Execution Chains

Ask:
- what triggers this
- what runs
- what restores it
- what privilege it gains
- what access it preserves

---

## Key Takeaway

Persistence analysis on Linux is deep, technical, and often non-obvious.

It takes time because the analyst is not merely searching for “bad files.” The analyst is reconstructing how an attacker made the system continue to trust and execute them over time.

That is exactly why Tenax should be used first.

> **Tenax helps the analyst spend time where time matters most. But real persistence analysis is complete only when the full attacker persistence chain is understood.**
