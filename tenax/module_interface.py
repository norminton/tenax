from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


AnalyzeFunc = Callable[[], list[dict[str, Any]]]
CollectFunc = Callable[..., list[dict[str, Any]]]


@dataclass(frozen=True)
class ScoringProfile:
    name: str = "default"
    module_score_delta: int = 0
    environment_score_deltas: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class HeuristicProfile:
    default_mode: str = "strict"
    supported_modes: tuple[str, ...] = ("strict", "expanded")


@dataclass(frozen=True)
class ModuleMetadata:
    name: str
    display_name: str
    description: str
    analyze_contract: str = "list[finding]"
    collect_contract: str = "list[artifact]"
    analysis_behavior: str = "path-driven built-in analyzer"
    collection_behavior: str = "path-driven built-in collector"
    scopes: tuple[str, ...] = ("system",)
    heuristic_profile: HeuristicProfile = field(default_factory=HeuristicProfile)
    scoring_profile: ScoringProfile = field(default_factory=ScoringProfile)
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class TenaxModule:
    metadata: ModuleMetadata
    analyze: AnalyzeFunc
    collect: CollectFunc

    @property
    def name(self) -> str:
        return self.metadata.name


def build_module_registry(*modules: TenaxModule) -> dict[str, TenaxModule]:
    registry: dict[str, TenaxModule] = {}
    for module in modules:
        registry[module.name] = module
    return registry


def apply_scoring_profile(
    score: int,
    module: TenaxModule | None,
    *,
    environment: str | None = None,
) -> int:
    if module is None:
        return score
    profile = module.metadata.scoring_profile
    adjusted = score + int(profile.module_score_delta)
    if environment:
        adjusted += int(profile.environment_score_deltas.get(environment, 0))
    return max(adjusted, 0)


def determine_environment_label(path_value: str | None, *, root_prefix: Path | None = None) -> str:
    if root_prefix:
        return "mounted-root"
    if not path_value:
        return "unknown"
    lowered = path_value.lower()
    if lowered.startswith("/home/") or lowered.startswith("/root/"):
        return "user"
    return "system"
