from tenax.checks.cron import collect_cron_locations
from tenax.checks.systemd import collect_systemd_locations
from tenax.reporter import output_results


def run_collection(output_path=None, output_format="text", hash_files=False) -> None:
    artifacts = []

    artifacts.extend(collect_cron_locations(hash_files=hash_files))
    artifacts.extend(collect_systemd_locations(hash_files=hash_files))

    output_results(
        mode="collect",
        results=artifacts,
        output_format=output_format,
        output_path=output_path,
    )