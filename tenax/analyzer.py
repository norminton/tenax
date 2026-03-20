from tenax.checks.cron import analyze_cron_locations
from tenax.reporter import output_results


def run_analysis(output_path=None, output_format="text", top=20) -> None:
    findings = []

    findings.extend(analyze_cron_locations())

    findings.sort(key=lambda item: item.get("score", 0), reverse=True)
    findings = findings[:top]

    output_results(
        mode="analyze",
        results=findings,
        output_format=output_format,
        output_path=output_path,
    )
