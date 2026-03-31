# Tenax

Tenax is a Linux persistence triage and evidence collection tool for incident response.

It is designed to help responders inspect known persistence surfaces, collect supporting artifacts, and understand what Tenax did and did not cover during a run. The current repository focuses on truthful local analysis and collection, not remote acquisition, orchestration, or response automation.

## Current Scope

Tenax currently provides two CLI workflows:

- `tenax analyze` runs the built-in analyzer modules, enriches and deduplicates findings, applies user-selected filters, prints a responder-friendly terminal slice, and always saves the full filtered result set under `output/`.
- `tenax collect` gathers artifacts from the built-in collection modules, follows bounded path references, and writes an investigation bundle under `output/`.

Built-in module families currently registered in the codebase:

- `at_jobs`
- `autostart_hooks`
- `capabilities`
- `containers`
- `cron`
- `environment_hooks`
- `ld_preload`
- `network_hooks`
- `pam`
- `rc_init`
- `shell_profiles`
- `ssh`
- `sudoers`
- `systemd`
- `tmp_paths`

## Scope And Limitations

Tenax is Linux-only. The codebase depends on Linux filesystem semantics and POSIX account metadata modules such as `pwd` and `grp`.
Linux or WSL Ubuntu is the authoritative runtime and test environment. Windows-native execution is not a supported parity target for Tenax analysis or test validation.

Tenax does not claim complete persistence coverage. It inspects the built-in surfaces above and reports limitations alongside results, including:

- module execution failures
- user-supplied filtering
- live-host versus mounted-root targeting
- user enumeration scope
- permission and access boundaries
- collection reference-depth limits

An absence of findings is not a claim that the system is clean unless the operator has also reviewed the run limitations and target coverage.

## Installation

Tenax now ships with `pyproject.toml` packaging metadata and a console entry point.

```bash
python -m pip install .
tenax --help
tenax --version
```

If pip falls back to a user install, the `tenax` launcher is typically written under
`$HOME/.local/bin`. Ensure that directory is present in `PATH`, or invoke the tool with
`python -m tenax.cli`.

For contributor workflows:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install pytest
```

Run those commands from Linux or WSL Ubuntu. Do not treat Windows-native `cmd.exe` or PowerShell test runs as authoritative for this repository.

## CLI Usage

Analyze the live host:

```bash
tenax analyze
```

Analyze a mounted target root and keep only higher-severity SSH and systemd findings:

```bash
tenax analyze \
  --root-prefix /mnt/forensics/image \
  --source ssh,systemd \
  --severity high \
  --sort severity \
  --top 25
```

Collect a structured investigation bundle:

```bash
tenax collect --mode structured
```

Collect an evidence bundle from a mounted target root:

```bash
tenax collect \
  --mode evidence \
  --root-prefix /mnt/forensics/image \
  --modules ssh,pam,systemd \
  --archive
```

List the registered analyzer and collector modules:

```bash
tenax list-modules --mode both
```

By default, both `tenax analyze` and `tenax collect` write runtime output under the project `output/`
directory when running from a source checkout, or under the current working directory's discovered
Tenax project root in editable/installed workflows. This avoids writing into `site-packages`.

## Example Analyze Output

This sample reflects the current text renderer in `tenax/reporter.py`.

```text
══════════════════════════════════════════════════════
              TENAX PERSISTENCE ANALYSIS
══════════════════════════════════════════════════════
🔥 CRITICAL FINDINGS: 1
HIGH FINDINGS: 1
MEDIUM FINDINGS: 0
LOW FINDINGS: 0
INFO FINDINGS: 0
Displayed: 2 of 2
Saved Findings: 2
Modules Succeeded: 2/2

Limitations:
- Only the selected analyzer modules were executed.
- Analysis targeted mounted root /mnt/forensics/image.
- User-scoped modules enumerated 3 local user home paths.
- Unreadable target paths may reduce observable findings; only accessible artifacts can be analyzed.

🔥 CRITICAL FINDINGS: 1
┌────────────────────────────────────────────┐
│ SYSTEMD (SYSTEM-LEVEL)                     │
└────────────────────────────────────────────┘

[CRITICAL] SYSTEMD SERVICE DEFINITION ANOMALY
ID: TX-SYSTEMD-8A15F2C1
User: system
File: /etc/systemd/system/dbus-update.service

Score: 115
Rule: TX-RULE-SYSTEMD-SERVICE_DEFINITION
Reason: systemd service executes payload from a temporary path

Exec:
  line 7 -> ExecStart=/tmp/.cache/dbus-update --daemon

Tags: root-execution, scheduled-start, service-definition, system-scope, systemd, systemd-unit, temp-path
------------------------------------------------------

HIGH FINDINGS: 1
┌────────────────────────────────────────────┐
│ SSH (USER PERSISTENCE)                     │
└────────────────────────────────────────────┘

[HIGH] SSH SUSPICIOUS PERSISTENCE ARTIFACT
ID: TX-SSH-4A32A7E0
User: root
File: /root/.ssh/authorized_keys

Score: 74
Rule: TX-RULE-SSH-SSH_PERSISTENCE
Reason: authorized_keys entry uses command= restriction/execution

Exec:
  command="/usr/local/bin/keywrap" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...

Tags: credential-surface, ssh, ssh-persistence, user-persistence, user-scope
------------------------------------------------------

══════════════════════════════════════════════════════
Output saved:
output/analyze_20260331_120000.txt
══════════════════════════════════════════════════════
```

## Example Collect Output

Current collection runs create a timestamped bundle and write a short terminal summary:

```text
=== TENAX COLLECT RESULTS ===
Mode: evidence
Artifacts: 3
References: 2
Errors: 0
Saved manifest to: /cases/tenax-output/collect_20260326_141530/manifest.json
Saved archive to: /cases/tenax-output/collect_20260326_141530.tgz
```

Saved bundle layout:

```text
output/
`-- collect_20260326_141530/
    |-- artifacts.json
    |-- errors.json
    |-- hashes.txt
    |-- manifest.json
    |-- references.json
    |-- summary.txt
    `-- collected/
        |-- ssh/
        |   `-- etc_ssh/sshd_config
        `-- ssh_reference/
            `-- opt/payload.sh
```

Representative `summary.txt` excerpt:

```text
=== TENAX COLLECT SUMMARY ===

Collection ID: collect_20260326_141530
Mode: evidence
Host: ir-workstation
User: analyst
Target Root: /

--- Totals ---
Artifacts collected: 3
Direct artifacts: 1
Reference artifacts: 2
References found: 2
Required references followed: 2 of 2
Artifacts copied: 3
Errors: 0
```

Additional examples are documented in [docs/usage-examples.md](docs/usage-examples.md).

## Repository Layout

```text
.
|-- docs/
|   |-- architecture.md
|   |-- usage-examples.md
|   |-- analyst-guide.md
|   `-- modules/
|-- output/
|-- tenax/
|   |-- analyzer.py
|   |-- cli.py
|   |-- collector.py
|   |-- reporter.py
|   |-- scope.py
|   `-- checks/
|-- tests/
|-- CONTRIBUTING.md
|-- LICENSE
|-- pyproject.toml
|-- pytest.ini
`-- tnx.py
```

## Development And Testing

Run the current test suite with:

```bash
python -m pytest
```

Run the suite on Linux or WSL Ubuntu. The GitHub Actions workflow is Ubuntu-based and is the authoritative CI environment for this project.

## Documentation

- [Contributor guide](CONTRIBUTING.md)
- [Architecture overview](docs/architecture.md)
- [Usage examples](docs/usage-examples.md)
- [Analyst playbook](docs/README.md)
- [Output schemas](docs/output-schemas.md)
- [Build workflow](docs/build-workflow.md)

## License

Tenax is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
