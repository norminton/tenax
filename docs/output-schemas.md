# Output Schemas

This document describes the public output fields Tenax currently writes. It reflects the current
repository behavior and should be updated whenever analyzer or collector output contracts change.

## Analyze Findings

Each finding in `tenax analyze --format json` includes:

- `finding_id`: stable display identifier derived from source and finding key
- `finding_key`: stable dedupe identity for the surviving finding entry
- `schema_version`: current analyze finding schema version
- `source` / `source_module`: primary module associated with the finding
- `sources`: all contributing modules when findings were merged
- `path`: primary artifact path shown to the analyst
- `normalized_path`: normalized target path used for dedupe/filtering
- `paths`: all path variants retained after dedupe
- `score`: strongest merged score
- `severity`: normalized severity derived from score
- `rule_id`: stable rule identifier for the finding context
- `rule_name`: human-readable rule label
- `reason`: primary analyst-facing reason
- `reasons`: all merged reasons for the retained context
- `tags`: normalized tags derived from module output and analyzer enrichment
- `scope`: `user`, `system`, `mixed`, or `unknown`
- `preview`: short evidence preview when available
- `evidence`: structured preview/reason/path evidence summary
- `rationale`: structured explanation bundle including summary, source, reasons, preview, tags, and paths
- `dedupe`: merged-count and contributing rule/source metadata
- `score_breakdown`: merged scoring context when multiple findings collapsed into one retained entry

## Analyze Metadata

Analyze output metadata currently includes:

- `summary`: finding counts, module success/failure counts, severities, sources, tags, and duration
- `filters`: user-applied filter and sort settings
- `selected_sources`: modules requested for the run
- `module_status`: per-module execution status, duration, finding count, error text, and module limitations
- `module_catalog`: registered module metadata for modules that ran
- `limitations`: explicit coverage, filtering, scope, dependency, and partial-coverage notes
- `scope`: root-prefix and enumerated user scope information

## Collect Manifest

`manifest.json` currently includes:

- `schema_version`
- `collection_id`
- `created_at`
- `mode` / `mode_description`
- `host` / `user`
- `baseline_name`
- `collection_profile`
- `options`
- `module_catalog`
- `summary`
- `scope`
- `limitations`
- `module_status`
- `artifacts`
- `references`
- `errors`

## Collect Artifacts

Each artifact record currently includes:

- identity and path fields: `id`, `module`, `artifact_type`, `path`, `normalized_path`, `host_path`
- discovery fields: `collection_mode`, `discovery_mode`, `discovered_from`, `reference_reason`
- filesystem metadata: `exists`, `is_file`, `is_dir`, `is_symlink`, `symlink_target`, `owner`, `group`, `mode`, `size`, `inode`, `mtime`, `ctime`
- evidence fields: `sha256`, `preview`, `content_capture`, `parsed`, `evidence`, `rationale`, `lineage`
- collection context: `limitations`, `references`, `copy_status`, `module_metadata`, `errors`

## Collect References

Each reference record currently includes:

- `id`
- `ref_type`
- `value`
- `reason`
- `parent_path`
- `parent_module`
- `depth`
- `discovery_method`
- `classification`
- `collection_required`
- `parent_artifact_id`
- `resolved_artifact_id`
- `resolved`
- `host_resolved`
- `exists`
- `followed`
- `copied`
- `copy_path`
- `parse_attempted`
- `errors`

## Limitations

Analyze and collect limitations currently use:

- `type`: broad limitation class such as `scope`, `partial_coverage`, `permissions`, `display`, `unsupported_dependency`
- `code`: stable machine-oriented limitation code
- `message`: analyst-facing explanation

Additional fields may appear depending on limitation type, including module names, filters, dependency
names, error counts, root-prefix context, user enumeration, excluded paths, and reference-depth settings.

## Collector Errors

Collector error objects currently expose:

- `type`: one of `permission_denied`, `missing_path`, `unsupported_dependency`, `parse_failure`, `module_failure`
- `message`: human-readable explanation
- `module`: module associated with the failure when known
- `path`: artifact or reference path when known
- `context`: structured supporting context when needed
- `detail`: exception class and message when available
