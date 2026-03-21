# Triage Principles

## Overview

Linux persistence triage is the process of deciding **where to spend analyst time first**.

That matters because Linux persistence can exist across many surfaces:

- services
- schedulers
- authentication
- startup files
- environment manipulation
- loaders
- containers
- event-driven hooks

A good triage process does not try to answer every question at once. It answers:

1. **What is most dangerous right now?**
2. **What is most likely to be attacker-controlled?**
3. **What can restore or preserve other persistence if left behind?**

> **The goal of triage is not speed for its own sake. The goal is to investigate in the order that makes it hardest for the attacker to survive.**

---

## Start With Tenax Analyze Mode

The first step in most persistence investigations should be:

```text
tenax analyze
```

or:

```text
python main.py analyze
```

If possible:

```text
sudo python main.py analyze
```

Use the output to identify:

- highest-scoring findings
- high-risk execution paths
- suspicious privilege or access mechanisms
- likely trigger-to-payload relationships

Tenax is not the full investigation. It is the tool that helps the analyst decide **what to inspect first**.

---

## Do Not Stop at the First Finding

One confirmed persistence mechanism does **not** mean it is the only one.

Attackers frequently layer persistence:

- one mechanism for execution
- one for access
- one for privilege re-entry
- one for recovery if another is removed

This is especially true if the attacker had:

- root access
- repeated interactive access
- time on the host

> **The first finding should narrow the search, not end it.**

---

## Triage by Effect, Not Just Mechanism

Do not triage findings only by their category name.

Instead, ask what the finding actually gives the attacker:

- **access**  
  Example: SSH keys

- **privilege**  
  Example: sudoers abuse, capabilities

- **automatic execution**  
  Example: systemd, cron, RC/init

- **stealthy execution hijack**  
  Example: `LD_PRELOAD`, environment hooks, PAM

- **recovery or restoration**  
  Example: network hook or `at` job that recreates persistence

A lower-profile mechanism that restores higher-value persistence may be more important than the more obvious artifact.

---

## Core Triage Questions

For each finding, ask:

### 1. What triggers execution?
Is it tied to:
- boot
- login
- authentication
- network events
- time
- container restart

### 2. What actually runs?
The config line is often not the payload.

Find:
- script
- binary
- shared object
- container command
- referenced file path

### 3. What privilege context does it use?
Does it run as:
- root
- service account
- regular user
- session user

### 4. Can it restore other persistence?
Does it:
- rewrite cron
- reinstall SSH keys
- recreate a service
- re-stage a payload

### 5. Does it preserve access directly?
Examples:
- SSH keys
- PAM backdoors
- sudoers abuse
- capability-enabled binaries

---

## Practical Priority Order

In most cases, a good starting order is:

### 1. Authentication and access preservation
- PAM
- SSH
- sudoers
- capabilities

### 2. Automatic privileged execution
- systemd
- root cron
- RC/init
- privileged containers

### 3. Stealth execution hijack
- `LD_PRELOAD`
- environment hooks
- loader abuse

### 4. User-triggered execution
- shell profiles
- autostart hooks
- user-level services

### 5. Delayed or event-driven support mechanisms
- `at` jobs
- network hooks
- temporary payload staging

This is not a rigid ranking for every host, but it is a strong default.

---

## Trigger, Payload, and Recovery Layer

Strong triage separates findings into three roles.

### Trigger
What causes execution?

Examples:
- cron entry
- systemd unit
- PAM auth line
- autostart entry

### Payload
What actually runs?

Examples:
- `/tmp/run.sh`
- `/usr/local/bin/.svc`
- `/tmp/libhook.so`

### Recovery Layer
What recreates persistence if something is removed?

Examples:
- network hook rewriting cron
- `at` job restoring SSH keys
- startup script reinstalling a service

A lot of investigations fail because the analyst finds the trigger but misses the payload or recovery layer.

---

## Host Context Matters

Triage should change depending on the host.

### Workstations and laptops
Prioritize:
- autostart
- shell profiles
- SSH
- network hooks
- user session behavior

### Servers
Prioritize:
- systemd
- cron
- PAM
- SSH
- sudoers
- capabilities

### Container hosts
Prioritize:
- container runtime state
- restart policies
- orchestration definitions
- Docker socket abuse
- host-pivot persistence

A persistence mechanism only matters if it can actually execute in that environment.

---

## Safe Triage Principles

When you find something suspicious:

1. preserve it before removing it
2. capture contents and metadata
3. identify what it references
4. determine whether it executed
5. determine whether it restores anything else

Do not test suspicious payloads by running them on the live host.

Do not assume deleting the visible artifact is enough.

---

## Signs a Finding Deserves Immediate Attention

Move a finding higher if it involves:

- root-level execution
- authentication interception
- direct access preservation
- execution from `/tmp`, `/var/tmp`, or `/dev/shm`
- remote retrieval and execution
- hidden payloads
- restoration of other persistence
- suspicious loader or PAM behavior

---

## Common Triage Mistakes

### 1. Starting too broad
Reviewing everything manually before checking the highest-risk findings wastes time.

### 2. Treating all findings equally
A root SSH key and a strange alias are not the same priority.

### 3. Ignoring restoration logic
Some low-visibility findings matter because they recreate more obvious persistence.

### 4. Stopping too early
One confirmed mechanism rarely means the host is fully understood.

---

## Key Takeaway

Good triage is disciplined prioritization.

The analyst should always work toward understanding:

- what preserves attacker access
- what preserves attacker privilege
- what guarantees attacker execution
- what restores the rest if missed

> **Triage is successful when the analyst investigates in the order that gives the attacker the fewest chances to stay on the box.**
