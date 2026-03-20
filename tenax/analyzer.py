from tenax.checks.at_jobs import analyze_at_job_locations
from tenax.checks.autostart_hooks import analyze_autostart_hook_locations
from tenax.checks.capabilities import analyze_capabilities
from tenax.checks.containers import analyze_container_locations
from tenax.checks.cron import analyze_cron_locations
from tenax.checks.environment_hooks import analyze_environment_hook_locations
from tenax.checks.ld_preload import analyze_ld_preload_locations
from tenax.checks.network_hooks import analyze_network_hook_locations
from tenax.checks.pam import analyze_pam_locations
from tenax.checks.rc_init import analyze_rc_init_locations
from tenax.checks.shell_profiles import analyze_shell_profile_locations
from tenax.checks.ssh import analyze_ssh_locations
from tenax.checks.sudoers import analyze_sudoers_locations
from tenax.checks.systemd import analyze_systemd_locations
from tenax.checks.tmp_paths import analyze_tmp_paths
from tenax.reporter import output_results


def _tag_results(source: str, results: list[dict]) -> list[dict]:
    tagged = []

    for item in results:
        enriched = dict(item)
        enriched["source"] = source
        tagged.append(enriched)

    return tagged


def run_analysis(output_path=None, output_format="text", top=20) -> None:
    findings = []

    module_results = {
        "cron": analyze_cron_locations(),
        "systemd": analyze_systemd_locations(),
        "shell_profiles": analyze_shell_profile_locations(),
        "ssh": analyze_ssh_locations(),
        "sudoers": analyze_sudoers_locations(),
        "rc_init": analyze_rc_init_locations(),
        "tmp_paths": analyze_tmp_paths(),
        "ld_preload": analyze_ld_preload_locations(),
        "autostart_hooks": analyze_autostart_hook_locations(),
        "network_hooks": analyze_network_hook_locations(),
        "pam": analyze_pam_locations(),
        "at_jobs": analyze_at_job_locations(),
        "containers": analyze_container_locations(),
        "environment_hooks": analyze_environment_hook_locations(),
        "capabilities": analyze_capabilities(),
    }

    print("\n=== MODULE SUMMARY ===")
    for module, results in module_results.items():
        print(f"{module}: {len(results)} findings")
    print("")

    for module, results in module_results.items():
        findings.extend(_tag_results(module, results))

    findings.sort(key=lambda item: item.get("score", 0), reverse=True)
    findings = findings[:top]

    output_results(
        mode="analyze",
        results=findings,
        output_format=output_format,
        output_path=output_path,
    )