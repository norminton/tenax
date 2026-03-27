# Tenax Architecture

This document describes the current implementation in the repository. It is not a forward-looking design document.

## Runtime Flow

### 1. CLI dispatch

`tenax/cli.py` builds the command-line parser and dispatches to one of two entry points:

- `tenax analyze` -> `tenax.analyzer.run_analysis`
- `tenax collect` -> `tenax.collector.run_collection`

The CLI is responsible for:

- argument parsing
- command-specific option validation
- banner opt-in
- passing normalized arguments into the analyzer or collector

### 2. Scope construction

Both execution paths call `tenax.scope.build_scan_scope(...)` before module execution.

That scope object carries the current target context, including:

- live-host or mounted-root targeting
- discovered local users from the target root
- target-to-host path translation
- watched locations for user-scoped and system-scoped modules

This is how Tenax supports offline or mounted-root inspection with `--root-prefix`.

### 3. Module registry

`tenax/checks/__init__.py` is the module registry. It builds `BUILTIN_MODULES` and exposes:

- `ANALYZE_SOURCES`
- `COLLECT_SOURCES`

Each module entry includes metadata plus two callables:

- an analyzer function
- a collector function

The metadata is used later for output catalogs, scoring context, and scope descriptions.

## Analyze Path

`tenax.analyzer.run_analysis` orchestrates analyzer execution.

Current steps:

1. Select modules from the registry.
2. Apply the current scan scope with `apply_module_scope(...)`.
3. Execute each analyzer module through `_safe_invoke_module(...)`.
4. Enrich each raw finding with normalized path data, rule metadata, tags, scope, rationale, and stable finding IDs.
5. Merge duplicate findings by normalized path and reason context.
6. Apply user-requested filters such as severity, source, path substring, writability, existence, and scope.
7. Sort the full filtered result set, assign stable finding IDs across that full set, and then truncate only the visible terminal slice.
8. Build summary and limitation metadata.
9. Hand the rendered output to `tenax.reporter.output_results(...)`.

### Analyze output

The reporter writes:

- an automatic output file under the project-local `output/` directory resolved from the current repository root
- an optional explicit output file if `--output` is provided
- a terminal rendering of the first few results

The analyzer currently supports `text` and `json` output formats.

## Collect Path

`tenax.collector.run_collection` orchestrates collection and bundle creation.

Current steps:

1. Validate the requested collection mode.
2. Build `CollectionOptions` from CLI arguments and mode defaults.
3. Create a timestamped output directory under `output/` or the user-supplied path.
4. Execute each registered collector module under the current scan scope.
5. Ingest direct artifacts into structured `ArtifactRecord` objects.
6. Parse direct execution-linked and supporting references from collected content.
7. Follow eligible path references up to the configured depth.
8. Ingest referenced artifacts and attach lineage back to the parent artifact.
9. Write bundle files: `manifest.json`, `artifacts.json`, `references.json`, `errors.json`, `hashes.txt`, and `summary.txt`.
10. Optionally archive the run directory to `.tgz`.

### Collection modes

The current modes are defined in `COLLECTION_MODE_PROFILES`:

- `minimal`: preservation-oriented copied artifacts with reduced text persistence
- `structured`: parsed investigator records without copying by default
- `evidence`: parsed records plus copied direct and reference artifacts

## Data Model Overview

### Findings

Analyzer modules emit raw dictionaries. `tenax/analyzer.py` normalizes them into findings with fields such as:

- `finding_id`
- `rule_id`
- `rule_name`
- `severity`
- `score`
- `source_module`
- `path`
- `tags`
- `scope`
- `rationale`
- `evidence`
- `dedupe`

### Artifacts

Collector modules emit raw dictionaries that are transformed into `ArtifactRecord` objects with:

- normalized and host paths
- stat and ownership metadata
- optional SHA256 hashes
- content capture and parsed content
- rationale and lineage
- reference records
- copy status
- per-artifact errors and limitations

### Limitations

Both primary execution paths produce explicit limitation metadata. That metadata is part of the product contract because it tells an analyst whether the current result set reflects full, partial, filtered, or access-limited coverage.

## Reporter Responsibilities

`tenax/reporter.py` currently handles the analyze output renderer and file writing.

It is responsible for:

- rendering text or JSON analyze output
- saving auto-generated output files
- saving explicit output files when requested
- printing a bounded terminal view

Collection bundle writing currently remains in `tenax/collector.py`.

## Tests

The `tests/` directory covers:

- analyzer contract behavior
- collector contract behavior
- schema shapes
- fixture-backed module behavior for selected modules

Those tests are the current executable description of the live contracts.
