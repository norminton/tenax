from tenax.checks.cron import collect_cron_locations
from tenax.checks.rc_init import collect_rc_init_locations
from tenax.checks.shell_profiles import collect_shell_profile_locations
from tenax.checks.ssh import collect_ssh_locations
from tenax.checks.sudoers import collect_sudoers_locations
from tenax.checks.systemd import collect_systemd_locations
from tenax.checks.tmp_paths import collect_tmp_paths
from tenax.reporter import output_results


def run_collection(output_path=None, output_format="text", hash_files=False) -> None:
    artifacts = []

    artifacts.extend(collect_cron_locations(hash_files=hash_files))
    artifacts.extend(collect_systemd_locations(hash_files=hash_files))
    artifacts.extend(collect_shell_profile_locations(hash_files=hash_files))
    artifacts.extend(collect_ssh_locations(hash_files=hash_files))
    artifacts.extend(collect_sudoers_locations(hash_files=hash_files))
    artifacts.extend(collect_rc_init_locations(hash_files=hash_files))
    artifacts.extend(collect_tmp_paths(hash_files=hash_files))

    output_results(
        mode="collect",
        results=artifacts,
        output_format=output_format,
        output_path=output_path,
    )