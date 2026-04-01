# Tenax CLI Usage Guide

This guide documents the current Tenax CLI contract in the repository.

Tenax has two primary workflows:

- `tenax analyze` inspects persistence-related surfaces, enriches findings, applies filters, prints a terminal view, and saves the full filtered result set.
- `tenax collect` gathers artifacts, extracts bounded references, and writes an investigation bundle to disk.

Use this document as the operator-facing reference for the current CLI behavior.

## Overview

Core commands:

```bash
tenax analyze
tenax collect --mode structured
tenax list-modules --mode both
```

Built-in module names currently registered for both analysis and collection:

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

By default, Tenax writes runtime output under the repository `output/` directory.

## Quick Start

Analyze the live host:

```bash
tenax analyze
```

Show only higher-severity SSH and systemd findings:

```bash
tenax analyze --source ssh,systemd --severity high --sort severity --top 25
```

Analyze a mounted root instead of the live host:

```bash
tenax analyze --root-prefix /mnt/forensics/image
```

Write analyze output as JSON to an explicit file:

```bash
tenax analyze --format json --output /cases/analysis/tenax-analyze.json
```

Create a structured collection bundle:

```bash
tenax collect --mode structured
```

Create a preservation-oriented copied bundle:

```bash
tenax collect --mode minimal
```

Create a full evidence bundle and archive it:

```bash
tenax collect --mode evidence --archive
```

Collect from a mounted root with selected modules:

```bash
tenax collect \
  --mode evidence \
  --root-prefix /mnt/forensics/image \
  --modules ssh,pam,systemd
```

List registered modules:

```bash
tenax list-modules --mode both
```

## Analyze Command

Purpose:

- Run the built-in analyzer modules.
- Normalize, score, deduplicate, sort, and filter findings.
- Show a terminal display slice of the filtered result set.
- Save the full filtered result set to disk on every run.

Basic syntax:

```bash
tenax analyze [options]
```

Current parser examples:

```bash
tenax analyze
tenax analyze --severity high
tenax analyze --source ssh,pam,systemd
tenax analyze --path-contains .ssh
tenax analyze --only-writable --only-existing
```

### Analyze Options

General options:

- `-o, --output PATH`
  Save an additional copy of the full rendered output to a specific file, or into a specific directory.
- `--format {text,json}`
  Output format for terminal rendering and saved artifacts. Default: `text`.
- `--root-prefix PATH`
  Analyze a mounted or offline target root instead of the live host root.
- `--top N`
  Maximum number of findings shown in the terminal after filtering and dedupe. Default: `20`.
- `--sort {score,severity,path,source}`
  Sort key for the filtered findings. Default: `score`.

Filtering options:

- `--severity {info,low,medium,high,critical}`
  Minimum severity to include.
- `--source NAME1,NAME2,...`
  Limit results to specific source modules.
- `--path-contains STRING`
  Keep only findings whose path contains a substring.
- `--only-writable`
  Keep only findings tagged `writable`, `group-writable`, or `world-writable`.
- `--only-existing`
  Keep only findings whose current host path exists on disk.
- `--scope {user,system}`
  Restrict results to user-scoped or system-scoped findings.

Display and runtime options:

- `--banner`
  Show the startup banner before execution.
- `--quiet`
  Suppress the analyze summary and limitations section in text output. Findings and saved-path messages are still printed.
- `--verbose`
  Print per-module execution status lines during analysis.

### Analyze Behavior Notes

- `analyze` always writes a timestamped artifact under the repo `output/` directory, such as `output/analyze_20260401_101530.txt`.
- `--top` only limits what is shown in the terminal. The saved analyze artifact still contains the full filtered finding set.
- If `--output` points to a file, Tenax writes an additional copy to that exact file.
- If `--output` points to a directory that already exists, Tenax writes an additional timestamped file inside that directory.
- Text output starts with a summary block, then groups findings by severity and then by module.
- Each finding shows a title, finding ID, file path, score, rule ID, reason, optional preview block, and tags.
- Preview text is labeled as `Exec:` for `line N: ...`, `ExecStart=...`, `Exec=...`, and `command=...` previews. Other previews are labeled as `Evidence:`.
- In text mode, the footer uses `Output saved:` and prints the default saved path plus any additional explicit output path.
- JSON output includes:
  - `mode`
  - `count`
  - `metadata`
  - `results`
- In JSON mode, the terminal prints only the displayed slice, then prints `Saved full analyze output to:` and, if applicable, `Saved additional analyze output to:`.
- Analyze metadata includes summary counts, module status, applied filters, scope details, and limitations.
- With `--root-prefix`, finding paths stay target-root-relative, such as `/etc/...`, while root context is recorded in metadata.
- User-scoped modules enumerate users from the target root's `/etc/passwd` when available.

### Analyze Examples

Basic analyze of the live host:

```bash
tenax analyze
```

Show only the top 10 findings in the terminal:

```bash
tenax analyze --top 10
```

Filter to critical and high results, sorted by severity:

```bash
tenax analyze --severity high --sort severity
```

Focus on specific modules:

```bash
tenax analyze --source ssh,systemd,shell_profiles
```

Limit to user-scoped writable artifacts:

```bash
tenax analyze --scope user --only-writable
```

Limit to paths containing `.ssh`:

```bash
tenax analyze --path-contains .ssh
```

Show per-module execution details while analyzing:

```bash
tenax analyze --verbose
```

Analyze an offline image root and save JSON to an additional explicit file:

```bash
tenax analyze \
  --root-prefix /mnt/forensics/image \
  --source ssh,systemd \
  --severity high \
  --sort severity \
  --top 25 \
  --format json \
  --output /cases/analysis/tenax-image-analyze.json
```

Typical verbose line shape:

```text
[verbose] analyze module=systemd status=ok duration_ms=14.2 findings=3
[verbose] analyze module=cron status=error duration_ms=2.1 findings=0 error=RuntimeError: boom
```

### Analyze Sort Semantics

- `--sort score`
  Highest score first. This is the default.
- `--sort severity`
  Highest severity first: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
- `--sort path`
  Path name order.
- `--sort source`
  Source module name order.

For `score` and `severity`, Tenax sorts in descending order.
For `path` and `source`, Tenax sorts in ascending order.

### Analyze Output Example

Representative terminal text output for `tenax analyze --source ssh,systemd --severity high --top 2 --sort severity`:

```text
══════════════════════════════════════════════════════
              TENAX PERSISTENCE ANALYSIS
══════════════════════════════════════════════════════
🔥 CRITICAL FINDINGS: 1
HIGH FINDINGS: 1
MEDIUM FINDINGS: 0
LOW FINDINGS: 0
INFO FINDINGS: 0
Displayed: 2 of 3
Saved Findings: 3
Modules Succeeded: 2/2
Display truncated for terminal readability; saved artifact contains the full filtered result set.

Limitations:
- Only the selected analyzer modules were executed.
- Analysis targeted mounted root /mnt/forensics/image.
- User-scoped modules enumerated 3 local user home paths.
- Unreadable target paths may reduce observable findings; only accessible artifacts can be analyzed.

🔥 CRITICAL FINDINGS: 1
┌──────────────────────────┐
│ SYSTEMD (SYSTEM-LEVEL)   │
└──────────────────────────┘

[CRITICAL] SYSTEMD TEMPORARY-PATH EXECUTION
ID: TX-SYSTEMD-8A15F2C1
User: system
File: /etc/systemd/system/dbus-update.service

Score: 115
Rule: TX-RULE-SYSTEMD-TEMP_PATH
Reason: Systemd service executes payload from a temporary path

Exec:
  line 7 -> ExecStart=/tmp/.cache/dbus-update --daemon

Tags: root-execution, scheduled-start, service-definition, system-scope, systemd, systemd-unit, temp-path
------------------------------------------------------

HIGH FINDINGS: 1
┌──────────────────────────┐
│ SSH (USER PERSISTENCE)   │
└──────────────────────────┘

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
/path/to/repo/output/analyze_20260401_101530.txt
══════════════════════════════════════════════════════
```

If `--output /cases/analysis/tenax-analyze.txt` is also provided in text mode, the footer lists both paths:

```text
══════════════════════════════════════════════════════
Output saved:
/path/to/repo/output/analyze_20260401_101530.txt
/cases/analysis/tenax-analyze.txt
══════════════════════════════════════════════════════
```

Representative terminal behavior in JSON mode:

```text
{
  "mode": "analyze",
  "count": 2,
  "metadata": {
    "...": "terminal metadata reflects the displayed slice"
  },
  "results": [
    {
      "...": "only the displayed findings appear here"
    }
  ]
}
Saved full analyze output to: /path/to/repo/output/analyze_20260401_101530.json
Saved additional analyze output to: /cases/analysis/tenax-image-analyze.json
```

Representative saved JSON artifact structure:

```json
{
  "mode": "analyze",
  "count": 3,
  "metadata": {
    "schema_version": "1.1",
    "summary": {
      "module_success_count": 2,
      "module_count": 2,
      "module_error_count": 0,
      "filtered_finding_count": 3,
      "displayed_finding_count": 2,
      "saved_finding_count": 3,
      "display_truncated": true,
      "severity_counts": {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
      }
    },
    "filters": {
      "severity": "high",
      "sources": [
        "ssh",
        "systemd"
      ],
      "sort": "severity",
      "top": 25
    },
    "scope": {
      "root_prefix": "/mnt/forensics/image",
      "target_root": "/",
      "all_users": [
        "root",
        "alice",
        "bob"
      ]
    }
  },
  "results": [
    {
      "finding_id": "TX-SYSTEMD-8A15F2C1",
      "rule_id": "TX-RULE-SYSTEMD-TEMP_PATH",
      "rule_name": "systemd temporary-path execution",
      "severity": "CRITICAL",
      "score": 115,
      "source": "systemd",
      "source_module": "systemd",
      "path": "/etc/systemd/system/dbus-update.service",
      "scope": "system",
      "tags": [
        "root-execution",
        "scheduled-start",
        "service-definition",
        "system-scope",
        "systemd",
        "systemd-unit",
        "temp-path"
      ],
      "preview": "line 7: ExecStart=/tmp/.cache/dbus-update --daemon",
      "paths": [
        "/etc/systemd/system/dbus-update.service"
      ]
    }
  ]
}
```

Terminal versus saved output:

- Terminal text output shows at most `--top` findings, but the summary still shows `Displayed: X of Y` and `Saved Findings: Y`.
- The saved artifact always contains the full filtered result set after dedupe, sorting, and filters.
- `--quiet` removes the text-mode summary and `Limitations:` section, but findings and the `Output saved:` footer still print.
- Module failures are not shown inline with findings. They are reflected in `Module Failures: N` and in the `Limitations:` list when failures occurred.
- If no findings match the current filters, text output prints `No findings matched the current filters.` and still includes the saved output footer.

## Collect Command

Purpose:

- Run the built-in collection modules.
- Capture structured artifact records.
- Extract and follow bounded path references.
- Optionally copy artifacts and package a `.tgz` archive.
- Write a collection bundle with manifest, summaries, errors, references, and hashes.

Basic syntax:

```bash
tenax collect --mode {minimal|structured|evidence} [options]
```

Current parser examples:

```bash
tenax collect --mode minimal
tenax collect --mode structured --modules ssh,pam,shell_profiles
tenax collect --mode evidence --archive
```

### Collect Options

General options:

- `-o, --output PATH`
  Base output directory for collection runs.
- `--root-prefix PATH`
  Collect from a mounted or offline target root instead of the live host root.
- `--hash`
  Calculate SHA256 hashes for collected files. Enabled by default.
- `--no-hash`
  Disable SHA256 hashing.
- `--baseline-name NAME`
  Optional baseline label stored in the collection outputs.
- `--banner`
  Show the startup banner before execution.

Collection mode:

- `--mode {minimal,structured,evidence}`
  Required. Selects the collection profile.

Module selection:

- `--modules NAME1,NAME2,...`
  Limit collection to specific modules.

Reference handling:

- `--no-follow-references`
  Disable opportunistic secondary reference recursion. References marked as collection-required are still followed.
- `--max-reference-depth N`
  Maximum reference recursion depth. Default: `2`.

File handling:

- `--max-file-size BYTES`
  Maximum number of bytes captured from text files. Default: `2097152` (2 MiB).
- `--max-hash-size BYTES`
  Maximum file size eligible for hashing. Default: `10485760` (10 MiB).

Archive options:

- `--archive`
  Package the collection run directory into a `.tgz` archive.

Filtering:

- `--exclude-path STRING`
  Exclude paths containing a substring. May be repeated.

### Collect Modes

`minimal`

- Preservation-oriented copied bundle.
- Copies direct artifacts.
- Copies followed references.
- Does not persist full or truncated text capture in artifact records.
- Parsed detail level is `minimal`.

Use it when:

- you want a lighter-weight preservation bundle
- copying files matters more than keeping structured text content

`structured`

- Investigator-grade parsed records.
- Does not copy files by default.
- Persists text capture and parsed structures in the manifest bundle.
- Still follows references and records them, subject to depth and exclusion rules.
- Parsed detail level is `structured`.

Use it when:

- you want reviewable JSON records first
- you are validating what Tenax parsed without copying every artifact

`evidence`

- Structured records plus copied artifact bundle.
- Copies direct artifacts.
- Copies followed references.
- Persists text capture and parsed structures.

Use it when:

- you want both parsed context and preserved artifacts
- you are preparing a handoff-ready evidence bundle

### Collect Behavior Notes

- `collect` requires `--mode`. There is no default mode at the CLI layer.
- Output is written to a timestamped run directory named like `collect_YYYYMMDD_HHMMSS`.
- If `--output` is omitted, the run directory is created under `output/`.
- If `--output` is provided, it is treated as the base directory, and Tenax creates the run directory inside it.
- `--archive` creates a sibling `.tgz` next to the run directory.
- `--exclude-path` supplements built-in exclusions. The collector also excludes these path substrings by default:
  - `/proc/`
  - `/sys/`
  - `/dev/pts/`
  - `/run/user/`
  - `/usr/share/doc/`
  - `/usr/share/man/`
  - `/usr/share/help/`
  - `/usr/share/info/`
- Reference following is path-only. Non-path references are recorded but not followed as collected artifacts.
- A required execution-linked or support-linked path reference may still be followed when `--no-follow-references` is set.
- `--max-reference-depth` limits recursion depth and can produce collection errors when deeper references are found but not followed.
- With `--root-prefix`, manifest paths stay target-root-relative such as `/etc/ssh/sshd_config`, while `host_path` stores the mounted-root location.
- User-scoped collection paths expand across discovered users from the target root's `/etc/passwd` when present.

### Collect Examples

Create a basic structured collection:

```bash
tenax collect --mode structured
```

Create a minimal copied bundle:

```bash
tenax collect --mode minimal
```

Create a full evidence bundle and archive it:

```bash
tenax collect --mode evidence --archive
```

Limit collection to a few modules:

```bash
tenax collect --mode structured --modules ssh,pam,systemd
```

Collect from an offline root:

```bash
tenax collect --mode evidence --root-prefix /mnt/forensics/image
```

Disable optional secondary reference following:

```bash
tenax collect --mode minimal --no-follow-references
```

Reduce reference recursion depth:

```bash
tenax collect --mode structured --max-reference-depth 1
```

Disable hashing:

```bash
tenax collect --mode structured --no-hash
```

Exclude specific paths:

```bash
tenax collect \
  --mode evidence \
  --exclude-path /opt/ignore-me \
  --exclude-path skip-me.sh
```

Write collection runs under a case directory:

```bash
tenax collect --mode evidence --output /cases/collections
```

Label a collection run:

```bash
tenax collect --mode structured --baseline-name pre-remediation
```

### Collect Output Example

Representative terminal summary:

```text
=== TENAX COLLECT RESULTS ===
Mode: evidence
Artifacts: 4
References: 3
Errors: 0
Saved manifest to: /cases/collections/collect_20260327_111530/manifest.json
Saved archive to: /cases/collections/collect_20260327_111530.tgz
```

Representative bundle layout:

```text
collect_20260327_111530/
|-- artifacts.json
|-- errors.json
|-- hashes.txt
|-- manifest.json
|-- references.json
|-- summary.txt
`-- collected/
    |-- systemd/
    |   `-- etc_systemd_system/backupd.service
    `-- systemd_reference/
        `-- dev_shm/backupd
```

Representative `manifest.json` structure:

```json
{
  "schema_version": "2.0",
  "collection_id": "collect_20260327_111530",
  "mode": "evidence",
  "mode_description": "Full evidence bundle with parsed investigator context and preserved artifacts.",
  "options": {
    "mode": "evidence",
    "modules": [
      "ssh",
      "pam",
      "systemd"
    ],
    "hash_files": true,
    "follow_references": true,
    "copy_files": true,
    "copy_references": true,
    "archive": true,
    "max_file_size": 2097152,
    "max_hash_size": 10485760,
    "max_reference_depth": 2,
    "root_prefix": "/mnt/forensics/image",
    "persist_text_capture": true,
    "parsed_detail_level": "structured"
  },
  "summary": {
    "artifact_count": 4,
    "direct_artifact_count": 2,
    "reference_artifact_count": 2,
    "reference_count": 3,
    "required_reference_count": 2,
    "followed_required_reference_count": 2,
    "copied_artifact_count": 4,
    "error_count": 0
  },
  "scope": {
    "root_prefix": "/mnt/forensics/image",
    "target_root": "/",
    "all_users": [
      "root",
      "svc-backup",
      "analyst"
    ]
  }
}
```

Representative `summary.txt` excerpt:

```text
=== TENAX COLLECT SUMMARY ===

Collection ID: collect_20260327_111530
Mode: evidence
Host: ir-jumpbox
User: responder
Target Root: /

--- Totals ---
Artifacts collected: 4
Direct artifacts: 2
Reference artifacts: 2
References found: 3
Required references followed: 2 of 2
Artifacts copied: 4
Errors: 0
```

Representative artifact record fields in `artifacts.json`:

```json
{
  "id": "artifact-000001",
  "collection_mode": "structured",
  "module": "ssh",
  "artifact_type": "sshd_config",
  "path": "/etc/ssh/sshd_config",
  "host_path": "/mnt/forensics/image/etc/ssh/sshd_config",
  "discovery_mode": "direct",
  "sha256": "9f7d...",
  "parsed": {
    "format": "ssh-config"
  },
  "copy_status": {
    "copied": false,
    "copied_to": null
  }
}
```

## Common Workflows

Quick triage of the live host:

```bash
tenax analyze --top 20 --sort score
```

Review only likely high-signal findings:

```bash
tenax analyze --severity high --sort severity --top 50
```

Look only at SSH and systemd persistence surfaces:

```bash
tenax analyze --source ssh,systemd
```

Check only user-scoped writable persistence:

```bash
tenax analyze --scope user --only-writable
```

Analyze a mounted image and keep the full filtered JSON artifact:

```bash
tenax analyze \
  --root-prefix /mnt/forensics/image \
  --format json \
  --output /cases/analysis/offline-analyze.json
```

Create a structured review bundle without copying files:

```bash
tenax collect --mode structured --modules ssh,pam,systemd
```

Create a copied preservation bundle for offline review:

```bash
tenax collect --mode minimal --root-prefix /mnt/forensics/image
```

Create a handoff-ready evidence archive:

```bash
tenax collect \
  --mode evidence \
  --root-prefix /mnt/forensics/image \
  --modules ssh,pam,systemd,shell_profiles \
  --archive \
  --output /cases/collections
```

## Notes And Limitations

- Tenax reports limitations in both analysis and collection outputs. Review them before treating an empty result as meaningful.
- `analyze` filters affect only the final displayed and saved result set. Module execution still happens for the selected sources.
- `collect` can report partial coverage through `errors.json`, manifest limitations, and per-module status.
- Root-prefix workflows preserve target-root paths in output and store mounted-root locations separately as `host_path`.
- The startup banner is optional and disabled by default.
- This guide documents the current CLI in the repository, not aspirational behavior.
