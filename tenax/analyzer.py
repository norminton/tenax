from tenax.checks.cron import analyze_cron_locations
from tenax.checks.shell_profiles import analyze_shell_profile_locations
from tenax.checks.ssh import analyze_ssh_locations
from tenax.checks.systemd import analyze_systemd_locations
from tenax.reporter import output_results


def run_analysis(output_path=None, output_format="text", top=20) -> None:
    findings = []

    module_results = {
        "cron": analyze_cron_locations(),
        "systemd": analyze_systemd_locations(),
        "shell_profiles": analyze_shell_profile_locations(),
        "ssh": analyze_ssh_locations(),
    }

    # Print summary
    print("\n=== MODULE SUMMARY ===")
    for module, results in module_results.items():
        print(f"{module}: {len(results)} findings")
    print("")

    # Flatten results
    for results in module_results.values():
        findings.extend(results)

    findings.sort(key=lambda item: item.get("score", 0), reverse=True)
    findings = findings[:top]

    output_results(
        mode="analyze",
        results=findings,
        output_format=output_format,
        output_path=output_path,
    )