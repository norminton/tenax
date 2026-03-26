from __future__ import annotations

from tenax.checks.at_jobs import analyze_at_job_locations, collect_at_job_locations
from tenax.checks.autostart_hooks import analyze_autostart_hook_locations, collect_autostart_hook_locations
from tenax.checks.capabilities import analyze_capabilities, collect_capabilities
from tenax.checks.containers import analyze_container_locations, collect_container_locations
from tenax.checks.cron import analyze_cron_locations, collect_cron_locations
from tenax.checks.environment_hooks import analyze_environment_hook_locations, collect_environment_hook_locations
from tenax.checks.ld_preload import analyze_ld_preload_locations, collect_ld_preload_locations
from tenax.checks.network_hooks import analyze_network_hook_locations, collect_network_hook_locations
from tenax.checks.pam import analyze_pam_locations, collect_pam_locations
from tenax.checks.rc_init import analyze_rc_init_locations, collect_rc_init_locations
from tenax.checks.shell_profiles import analyze_shell_profile_locations, collect_shell_profile_locations
from tenax.checks.ssh import analyze_ssh_locations, collect_ssh_locations
from tenax.checks.sudoers import analyze_sudoers_locations, collect_sudoers_locations
from tenax.checks.systemd import analyze_systemd_locations, collect_systemd_locations
from tenax.checks.tmp_paths import analyze_tmp_paths, collect_tmp_paths
from tenax.module_interface import ModuleMetadata, TenaxModule, build_module_registry


BUILTIN_MODULES = build_module_registry(
    TenaxModule(
        metadata=ModuleMetadata(
            name="cron",
            display_name="Cron",
            description="Analyze cron persistence surfaces.",
            scopes=("system",),
            tags=("scheduled-start",),
        ),
        analyze=analyze_cron_locations,
        collect=collect_cron_locations,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="systemd",
            display_name="Systemd",
            description="Analyze systemd unit and timer persistence surfaces.",
            scopes=("system", "user"),
            tags=("service-definition", "scheduled-start"),
        ),
        analyze=analyze_systemd_locations,
        collect=collect_systemd_locations,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="shell_profiles",
            display_name="Shell Profiles",
            description="Analyze shell profile and startup hook persistence surfaces.",
            scopes=("system", "user"),
            tags=("user-persistence",),
        ),
        analyze=analyze_shell_profile_locations,
        collect=collect_shell_profile_locations,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="ssh",
            display_name="SSH",
            description="Analyze SSH configuration and key-based persistence surfaces.",
            scopes=("system", "user"),
            tags=("credential-surface", "user-persistence"),
        ),
        analyze=analyze_ssh_locations,
        collect=collect_ssh_locations,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="sudoers",
            display_name="Sudoers",
            description="Analyze sudo policy persistence and privilege delegation surfaces.",
            scopes=("system",),
            tags=("root-execution",),
        ),
        analyze=analyze_sudoers_locations,
        collect=collect_sudoers_locations,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="rc_init",
            display_name="RC Init",
            description="Analyze rc and init persistence surfaces.",
            scopes=("system",),
            tags=("scheduled-start",),
        ),
        analyze=analyze_rc_init_locations,
        collect=collect_rc_init_locations,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="tmp_paths",
            display_name="Temp Paths",
            description="Analyze suspicious executable artifacts in temporary paths.",
            scopes=("system", "user"),
            tags=("temp-path",),
        ),
        analyze=analyze_tmp_paths,
        collect=collect_tmp_paths,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="ld_preload",
            display_name="LD Preload",
            description="Analyze dynamic linker preload persistence surfaces.",
            scopes=("system", "user"),
            tags=("root-execution",),
        ),
        analyze=analyze_ld_preload_locations,
        collect=collect_ld_preload_locations,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="autostart_hooks",
            display_name="Autostart Hooks",
            description="Analyze desktop autostart persistence surfaces.",
            scopes=("user",),
            tags=("scheduled-start", "user-persistence"),
        ),
        analyze=analyze_autostart_hook_locations,
        collect=collect_autostart_hook_locations,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="network_hooks",
            display_name="Network Hooks",
            description="Analyze network-triggered persistence surfaces.",
            scopes=("system",),
        ),
        analyze=analyze_network_hook_locations,
        collect=collect_network_hook_locations,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="pam",
            display_name="PAM",
            description="Analyze authentication hook persistence surfaces.",
            scopes=("system",),
            tags=("root-execution", "auth-hook"),
        ),
        analyze=analyze_pam_locations,
        collect=collect_pam_locations,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="at_jobs",
            display_name="At Jobs",
            description="Analyze at-job persistence surfaces.",
            scopes=("system", "user"),
            tags=("scheduled-start",),
        ),
        analyze=analyze_at_job_locations,
        collect=collect_at_job_locations,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="containers",
            display_name="Containers",
            description="Analyze container-related persistence surfaces.",
            scopes=("system", "user"),
            tags=("container-hook",),
        ),
        analyze=analyze_container_locations,
        collect=collect_container_locations,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="environment_hooks",
            display_name="Environment Hooks",
            description="Analyze environment-driven persistence surfaces.",
            scopes=("system", "user"),
            tags=("user-persistence",),
        ),
        analyze=analyze_environment_hook_locations,
        collect=collect_environment_hook_locations,
    ),
    TenaxModule(
        metadata=ModuleMetadata(
            name="capabilities",
            display_name="Capabilities",
            description="Analyze Linux capability-based persistence surfaces.",
            scopes=("system",),
            tags=("capabilities",),
        ),
        analyze=analyze_capabilities,
        collect=collect_capabilities,
    ),
)

ANALYZE_SOURCES = {name: module.analyze for name, module in BUILTIN_MODULES.items()}
COLLECT_SOURCES = {name: module.collect for name, module in BUILTIN_MODULES.items()}
