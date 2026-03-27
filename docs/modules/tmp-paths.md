# Temporary Path Abuse in Persistence

## Overview

Temporary directories such as `/tmp`, `/var/tmp`, and `/dev/shm` are not persistence mechanisms themselves. However, they are heavily used by attackers as staging locations for payloads that are later executed through persistence mechanisms.

These paths are designed for temporary storage and are typically:

- world-writable  
- frequently ignored during analysis  
- not expected to contain persistent system logic  

Because of these characteristics, attackers frequently leverage them to store:

- scripts  
- binaries  
- shared objects (`.so`)  
- staging payloads  

> **Temporary paths are not where persistence is defined — they are where persistence payloads often live.**

---

## Why Attackers Use Temporary Paths

Temporary directories provide attackers with:

- Write access without elevated privileges (in many cases)  
- Minimal operational friction  
- Reduced scrutiny compared to system directories  
- Easy cleanup or replacement of payloads  
- Compatibility with multiple persistence mechanisms  

Rather than embedding full payloads into configuration files, attackers often:

- store payloads in temporary paths  
- reference them from persistence mechanisms  

---

## Common Temporary Paths

### `/tmp`
- World-writable  
- Often cleared on reboot (depending on system)  
- Most commonly abused  

### `/var/tmp`
- Similar to `/tmp`  
- Often **persists across reboots**  
- More reliable for longer-term staging  

### `/dev/shm`
- Memory-backed filesystem  
- No disk persistence  
- Useful for stealth and reduced forensic artifacts  

---

## How Temporary Paths Support Persistence

Temporary paths are commonly used in combination with:

- cron jobs  
- systemd services  
- shell profiles  
- environment hooks  
- PAM hooks  
- RC/init scripts  

Example pattern:

- Persistence mechanism → triggers execution  
- Temporary path → stores payload  

---

## Common Attacker Tradecraft

### 1. Cron Job Executing Payload from `/tmp`

Example:

```text
echo "* * * * * /tmp/run.sh" >> /etc/crontab
```

Execution flow:
1. Attacker places script in `/tmp/run.sh`  
2. Cron job is created  
3. System executes script every minute  
4. Payload runs repeatedly  

Why attackers use this:
- Simple deployment  
- Easy to modify payload without touching cron  
- Separates trigger from payload  

---

### 2. Systemd Service Executing from Temporary Path

Example:

```text
ExecStart=/tmp/update.sh
```

Execution flow:
1. Attacker creates systemd service  
2. Points execution to `/tmp/update.sh`  
3. Service runs at boot or on trigger  
4. Payload executes under service context  

Why attackers use this:
- Avoids placing payload in monitored directories  
- Easy to swap payload  

---

### 3. LD_PRELOAD Using `/tmp` Shared Object

Example:

```text
LD_PRELOAD=/tmp/libhook.so
```

Execution flow:
1. Attacker drops malicious `.so` file in `/tmp`  
2. Environment or preload mechanism is configured  
3. Dynamic linker loads malicious library  
4. Code executes inside legitimate processes  

Why attackers use this:
- High stealth  
- Avoids modifying system library paths  
- Easy to replace payload  

---

## What Normal Looks Like

Legitimate usage of temporary paths typically includes:

- short-lived files  
- application caches  
- temporary processing data  
- installer artifacts  

Normal behavior:

- files are transient  
- not referenced by system startup mechanisms  
- not repeatedly executed  

### Default Tenax Noise Controls

By default, Tenax does not treat its own generated collection bundles as fresh temporary-path findings. Collection outputs such as `manifest.json`, `artifacts.json`, `references.json`, `hashes.txt`, `summary.txt`, and collected copies are suppressed when they appear inside Tenax `collect_YYYYMMDD_HHMMSS` output trees.

Obvious pytest-style harness directories are also suppressed by default so test fixtures in temporary directories do not pollute live-host triage output.

---

## What Malicious Use Looks Like

### High-Signal Indicators

- Execution from:
  - `/tmp`
  - `/var/tmp`
  - `/dev/shm`
- Scripts referenced by:
  - cron  
  - systemd  
  - PAM  
  - init scripts  
- `.so` files in temporary directories  
- Executable files with unusual names  
- Recently created files tied to persistence mechanisms  

### Medium-Signal Indicators

- Hidden files (e.g., `.cache`, `.update`)  
- Scripts with network activity  
- Repeated execution patterns  

### Low-Signal Indicators

- installer leftovers  
- temporary logs  
- application runtime files  

---

## Analytical Guidance

### Key Question

> Is a temporary path being used as a storage location for something that is repeatedly executed?

---

### Focus Areas

#### 1. Execution Linkage

Is the file in `/tmp` being referenced by:

- cron  
- systemd  
- PAM  
- shell profiles  
- init scripts  

#### 2. File Behavior

- Is it executable?  
- Does it contain:
  - network calls  
  - shell execution  
  - persistence logic  

#### 3. Lifetime

- Does the file persist longer than expected?  
- Is it recreated after deletion?  

#### 4. Naming Patterns

- Hidden files (`.something`)  
- Generic names (`update`, `run`, `cache`)  
- Masquerading names (`libcrypto.so`, `dbus-helper`)  

---

## Triage Workflow

1. Inspect temporary directories:

```text
ls -la /tmp
ls -la /var/tmp
ls -la /dev/shm
```

2. Identify executable or suspicious files  

3. Inspect contents  

4. Check metadata:

```text
stat /tmp/*
```

5. Correlate with persistence mechanisms  

6. Check for network or command execution  

---

## Evidence to Preserve

- files in `/tmp`, `/var/tmp`, `/dev/shm`  
- file metadata (timestamps, ownership, permissions)  
- referenced persistence mechanisms  
- network activity associated with execution  
- hashes of suspicious binaries or scripts  

---

## Why Tenax Checks This Surface

Temporary paths are not persistence mechanisms, but they are:

- the most common payload storage locations  
- frequently used across multiple persistence techniques  
- easy to overlook during analysis  

By identifying suspicious usage of temporary paths, Tenax helps analysts:

- connect persistence triggers to actual payloads  
- understand execution flow  
- detect staging behavior  

> The persistence mechanism tells you **when** something runs.  
> Temporary paths often tell you **what** is actually running.

---

## Key Takeaway

Temporary path abuse is not persistence by itself.

> It is the foundation that many persistence mechanisms rely on to store and execute malicious payloads.
