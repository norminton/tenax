#!/usr/bin/env bash
set -euo pipefail

# Tenax Ubuntu persistence validation corpus generator
#
# Safe-by-default design:
# - builds an offline Ubuntu-style root tree under /opt/tenax-lab/rootfs
# - creates inert payload placeholders only
# - never enables or starts services
# - never executes created artifacts
#
# Usage:
#   sudo ./generate_ubuntu_persistence_corpus.sh
#   sudo ROOT_PREFIX=/srv/tenax-lab/rootfs ./generate_ubuntu_persistence_corpus.sh
#
# Suggested analysis flow afterward:
#   tenax analyze --root-prefix /opt/tenax-lab/rootfs

LAB_BASE="${LAB_BASE:-/opt/tenax-lab}"
ROOT_PREFIX="${ROOT_PREFIX:-$LAB_BASE/rootfs}"
LOG_DIR="$LAB_BASE/log"
MANIFEST="$LAB_BASE/manifest.tsv"
SUMMARY="$LOG_DIR/summary.txt"
MARKER="$LAB_BASE/CREATED_BY_TENAX_VALIDATION"
RUN_LOG="$LOG_DIR/generator.log"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root so the script can create a realistic offline Ubuntu root tree under $LAB_BASE." >&2
  exit 1
fi

mkdir -p "$LAB_BASE" "$LOG_DIR"
touch "$RUN_LOG"

if [[ -d "$ROOT_PREFIX" ]]; then
  case "$ROOT_PREFIX" in
    "$LAB_BASE"/*) rm -rf -- "$ROOT_PREFIX" ;;
    *)
      echo "Refusing to remove unexpected ROOT_PREFIX: $ROOT_PREFIX" >&2
      exit 1
      ;;
  esac
fi

mkdir -p "$ROOT_PREFIX"
: > "$MANIFEST"
: > "$SUMMARY"
printf 'TENAX_VALIDATION_LAB=1\nLAB_BASE=%s\nROOT_PREFIX=%s\n' "$LAB_BASE" "$ROOT_PREFIX" > "$MARKER"
printf 'class\tcategory\tpath\tnote\n' >> "$MANIFEST"

log() {
  printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$RUN_LOG" >/dev/null
}

register_artifact() {
  local artifact_class="$1"
  local category="$2"
  local path="$3"
  local note="$4"
  printf '%s\t%s\t%s\t%s\n' "$artifact_class" "$category" "$path" "$note" >> "$MANIFEST"
}

ensure_dir() {
  mkdir -p "$1"
}

write_file() {
  local artifact_class="$1"
  local category="$2"
  local path="$3"
  local mode="$4"
  local note="$5"
  ensure_dir "$(dirname "$path")"
  cat > "$path"
  chmod "$mode" "$path"
  register_artifact "$artifact_class" "$category" "$path" "$note"
}

write_executable() {
  write_file "$1" "$2" "$3" 0755 "$4"
}

write_text() {
  local artifact_class="$1"
  local category="$2"
  local path="$3"
  local mode="$4"
  local note="$5"
  local content="$6"
  ensure_dir "$(dirname "$path")"
  printf '%s\n' "$content" > "$path"
  chmod "$mode" "$path"
  register_artifact "$artifact_class" "$category" "$path" "$note"
}

create_inert_script() {
  local path="$1"
  local label="$2"
  write_executable payload payload "$path" "inert script placeholder for $label" <<EOF
#!/usr/bin/env bash
set -euo pipefail
echo "Tenax validation placeholder: $label"
EOF
}

create_inert_binary_placeholder() {
  local path="$1"
  local label="$2"
  write_file payload payload "$path" 0644 "inert binary placeholder for $label" <<EOF
PLACEHOLDER ONLY
label=$label
purpose=tenax-validation
content=this-is-not-a-real-shared-object-or-binary
EOF
}

create_public_key() {
  local who="$1"
  printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOg91e0O2T8Wgq9O2k0fT4OycW2bM3uYbqX7Fd9R%02d %s@tenax-lab\n' "$2" "$who"
}

log "Creating Tenax validation corpus under $ROOT_PREFIX"

PERSONAS=(ubuntu analyst opsadmin buildsvc contractor dbmaint helpdesk release)

for persona in "${PERSONAS[@]}"; do
  ensure_dir "$ROOT_PREFIX/home/$persona"
  ensure_dir "$ROOT_PREFIX/home/$persona/.ssh"
  ensure_dir "$ROOT_PREFIX/home/$persona/.config/systemd/user"
  ensure_dir "$ROOT_PREFIX/home/$persona/.config/autostart"
  ensure_dir "$ROOT_PREFIX/home/$persona/.local/bin"
  ensure_dir "$ROOT_PREFIX/home/$persona/.cache"
  ensure_dir "$ROOT_PREFIX/home/$persona/.local/share"
  write_text benign metadata "$ROOT_PREFIX/home/$persona/.tenax-lab-persona" 0644 "persona marker" \
    "filesystem-only lab persona for Tenax validation"
done

BASE_DIRS=(
  "$ROOT_PREFIX/etc/systemd/system"
  "$ROOT_PREFIX/usr/lib/systemd/system"
  "$ROOT_PREFIX/etc/systemd/user"
  "$ROOT_PREFIX/etc/cron.d"
  "$ROOT_PREFIX/etc/anacrontab.d"
  "$ROOT_PREFIX/etc/cron.daily"
  "$ROOT_PREFIX/etc/cron.weekly"
  "$ROOT_PREFIX/etc/profile.d"
  "$ROOT_PREFIX/etc/pam.d"
  "$ROOT_PREFIX/etc/sudoers.d"
  "$ROOT_PREFIX/etc/init.d"
  "$ROOT_PREFIX/etc/rc.local.d"
  "$ROOT_PREFIX/etc/X11/Xsession.d"
  "$ROOT_PREFIX/etc/xdg/autostart"
  "$ROOT_PREFIX/usr/local/sbin"
  "$ROOT_PREFIX/usr/local/bin"
  "$ROOT_PREFIX/usr/local/lib"
  "$ROOT_PREFIX/usr/local/lib/systemd/system"
  "$ROOT_PREFIX/usr/local/etc/ld.so.conf.d"
  "$ROOT_PREFIX/etc/ld.so.conf.d"
  "$ROOT_PREFIX/opt/fleet/bin"
  "$ROOT_PREFIX/opt/operations/bin"
  "$ROOT_PREFIX/opt/admin/bin"
  "$ROOT_PREFIX/opt/vendor/hooks"
  "$ROOT_PREFIX/var/lib/tenax-lab/payloads"
  "$ROOT_PREFIX/var/lib/tenax-lab/cloud-init"
  "$ROOT_PREFIX/var/lib/tenax-lab/bootstrap"
  "$ROOT_PREFIX/var/tmp/.font-cache"
  "$ROOT_PREFIX/var/tmp/.cache-updates"
  "$ROOT_PREFIX/dev/shm/.dbus-cache"
  "$ROOT_PREFIX/run/user/1000/.x11"
  "$ROOT_PREFIX/tmp/.runtime"
  "$ROOT_PREFIX/usr/share/polkit-1/rules.d"
  "$ROOT_PREFIX/var/spool/cron/crontabs"
)

for dir in "${BASE_DIRS[@]}"; do
  ensure_dir "$dir"
done

create_inert_script "$ROOT_PREFIX/usr/local/sbin/logrotate-local" "benign log rotation wrapper"
create_inert_script "$ROOT_PREFIX/usr/local/sbin/asset-inventory-push" "benign asset inventory wrapper"
create_inert_script "$ROOT_PREFIX/usr/local/sbin/cert-audit-local" "benign local certificate audit"
create_inert_script "$ROOT_PREFIX/usr/local/sbin/patch-window-prep" "gray patch window prep helper"
create_inert_script "$ROOT_PREFIX/usr/local/sbin/local-session-audit" "gray pam audit helper"
create_inert_script "$ROOT_PREFIX/usr/local/bin/fleet-heartbeat" "benign fleet heartbeat helper"
create_inert_script "$ROOT_PREFIX/opt/fleet/bin/tray-health" "gray desktop tray health helper"
create_inert_script "$ROOT_PREFIX/opt/fleet/bin/cache-prune" "gray cache prune helper"
create_inert_script "$ROOT_PREFIX/opt/operations/bin/find-world-writable" "gray operations helper"
create_inert_script "$ROOT_PREFIX/opt/operations/bin/chown-scan" "gray ownership repair helper"
create_inert_script "$ROOT_PREFIX/opt/admin/bin/maintenance-window" "gray maintenance helper"
create_inert_script "$ROOT_PREFIX/opt/vendor/hooks/login-notice" "benign login notice helper"

create_inert_script "$ROOT_PREFIX/var/tmp/.font-cache/dbus-font-cache" "suspicious hidden tmp payload"
create_inert_script "$ROOT_PREFIX/var/tmp/.cache-updates/system-metricsd" "suspicious var tmp payload"
create_inert_script "$ROOT_PREFIX/dev/shm/.dbus-cache/session-check" "suspicious shm payload"
create_inert_script "$ROOT_PREFIX/run/user/1000/.x11/x11-cache-loader" "suspicious run-user payload"
create_inert_script "$ROOT_PREFIX/tmp/.runtime/pulse-session" "suspicious tmp payload"
create_inert_script "$ROOT_PREFIX/home/analyst/.cache/.profile-sync" "suspicious user cache payload"
create_inert_script "$ROOT_PREFIX/home/buildsvc/.local/share/.containerd-user" "suspicious hidden user payload"
create_inert_script "$ROOT_PREFIX/home/contractor/.config/.dbus-sessiond" "suspicious user config payload"
create_inert_script "$ROOT_PREFIX/home/dbmaint/.local/bin/.ssh-session-wrap" "suspicious ssh forced-command payload"
create_inert_binary_placeholder "$ROOT_PREFIX/var/tmp/.font-cache/libmtrace.so" "suspicious tmp preload"
create_inert_binary_placeholder "$ROOT_PREFIX/usr/local/lib/libjemalloc-profile.so" "benign preload-style performance library"
create_inert_binary_placeholder "$ROOT_PREFIX/usr/local/lib/libaudit-session.so" "gray preload-style audit library"
create_inert_binary_placeholder "$ROOT_PREFIX/home/ubuntu/.local/share/.libnss-cache.so" "suspicious user-writable loader reference"

for idx in $(seq 1 12); do
  create_inert_script "$ROOT_PREFIX/var/lib/tenax-lab/bootstrap/bootstrap-$idx.sh" "benign bootstrap snippet $idx"
done

BENIGN_SYSTEMD_SERVICES=(
  "apt-news-refresh:/usr/bin/systemd-notify --status=apt-news-refresh"
  "motd-facts-collect:/usr/bin/uname -a"
  "cert-audit-local:/usr/local/sbin/cert-audit-local"
  "asset-inventory-push:/usr/local/sbin/asset-inventory-push"
  "osquery-cache-prune:/usr/bin/find /var/cache/osquery -type f -mtime +7 -print"
  "cloud-cleanup-local:/usr/bin/find /var/lib/cloud/instance/scripts -maxdepth 1 -type f -print"
  "logrotate-local:/usr/local/sbin/logrotate-local"
  "backup-catalog-sync:/usr/bin/logger -t backup-catalog-sync offline-sync"
  "ca-bundle-refresh:/usr/sbin/update-ca-certificates --fresh"
  "apt-mirror-health:/usr/bin/apt-cache policy"
  "package-cache-report:/usr/bin/du -sh /var/cache/apt/archives"
  "journal-vacuum-report:/usr/bin/journalctl --disk-usage"
  "inventory-snapshot:/usr/bin/dpkg -l"
  "motd-news-local:/usr/bin/printf 'maintenance window scheduled\n'"
  "rsyslog-local-health:/usr/bin/systemctl show rsyslog.service"
  "tmpfs-capacity-report:/usr/bin/df -h /run"
)

for entry in "${BENIGN_SYSTEMD_SERVICES[@]}"; do
  IFS=':' read -r name execstart <<< "$entry"
  write_file benign systemd "$ROOT_PREFIX/usr/lib/systemd/system/$name.service" 0644 "benign system service" <<EOF
[Unit]
Description=$name
Documentation=man:systemd.service(5)
After=network-online.target

[Service]
Type=oneshot
ExecStart=$execstart
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
done

BENIGN_SYSTEMD_TIMERS=(
  apt-news-refresh
  cert-audit-local
  asset-inventory-push
  backup-catalog-sync
  package-cache-report
  journal-vacuum-report
  inventory-snapshot
  motd-facts-collect
  tmpfs-capacity-report
  ca-bundle-refresh
)

for name in "${BENIGN_SYSTEMD_TIMERS[@]}"; do
  write_file benign systemd "$ROOT_PREFIX/usr/lib/systemd/system/$name.timer" 0644 "benign timer" <<EOF
[Unit]
Description=$name timer

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=15m
Unit=$name.service

[Install]
WantedBy=timers.target
EOF
done

SUSPICIOUS_SYSTEMD=(
  "systemd-userdbd-cache:/var/tmp/.cache-updates/system-metricsd --daemon"
  "dbus-session-helper:/bin/sh -c '/var/tmp/.font-cache/dbus-font-cache --quiet'"
  "containerd-userns:/usr/bin/python3 /home/buildsvc/.local/share/.containerd-user"
  "systemd-hostnamed-cache:/usr/bin/bash /tmp/.runtime/pulse-session"
  "udev-monitor-sync:/bin/dash /dev/shm/.dbus-cache/session-check"
  "networkd-dispatch-cache:/usr/bin/env bash /run/user/1000/.x11/x11-cache-loader"
  "snap-security-check:/usr/bin/perl /home/analyst/.cache/.profile-sync"
  "motd-cache-refresh:/usr/bin/python3 -c 'import os; os.system(\"/var/tmp/.cache-updates/system-metricsd\")'"
  "accounts-daemon-update:/usr/bin/env sh /home/contractor/.config/.dbus-sessiond"
  "uuidd-path-watcher:/bin/bash /var/tmp/.font-cache/dbus-font-cache --foreground"
  "session-store-cleanup:/usr/bin/env python3 /home/dbmaint/.local/bin/.ssh-session-wrap"
  "syslog-rotate-cache:/bin/sh -c '/var/tmp/.cache-updates/system-metricsd >/dev/null 2>&1'"
  "machine-id-refresh:/usr/bin/nohup /var/tmp/.font-cache/dbus-font-cache"
  "remote-fs-helper:/usr/bin/bash -lc '/tmp/.runtime/pulse-session'"
  "polkit-agent-cache:/usr/bin/env perl /dev/shm/.dbus-cache/session-check"
)

for entry in "${SUSPICIOUS_SYSTEMD[@]}"; do
  IFS=':' read -r name execstart <<< "$entry"
  write_file suspicious systemd "$ROOT_PREFIX/etc/systemd/system/$name.service" 0644 "suspicious system service" <<EOF
[Unit]
Description=$name
After=network.target

[Service]
Type=simple
ExecStart=$execstart
Restart=always
RestartSec=45

[Install]
WantedBy=multi-user.target
EOF
done

SUSPICIOUS_TIMERS=(
  systemd-userdbd-cache
  dbus-session-helper
  networkd-dispatch-cache
  snap-security-check
  machine-id-refresh
  remote-fs-helper
  syslog-rotate-cache
  polkit-agent-cache
)

for name in "${SUSPICIOUS_TIMERS[@]}"; do
  write_file suspicious systemd "$ROOT_PREFIX/etc/systemd/system/$name.timer" 0644 "suspicious timer" <<EOF
[Unit]
Description=$name timer

[Timer]
OnBootSec=5m
OnUnitActiveSec=17m
AccuracySec=1m
Unit=$name.service

[Install]
WantedBy=timers.target
EOF
done

for persona in "${PERSONAS[@]}"; do
  write_file benign user-systemd "$ROOT_PREFIX/home/$persona/.config/systemd/user/session-notes.service" 0644 "benign user service" <<EOF
[Unit]
Description=Session notes sync for $persona

[Service]
Type=oneshot
ExecStart=/usr/bin/printf '$persona session note sync\n'

[Install]
WantedBy=default.target
EOF

  write_file benign user-systemd "$ROOT_PREFIX/home/$persona/.config/systemd/user/cache-prune.service" 0644 "benign user service" <<EOF
[Unit]
Description=Cache prune for $persona

[Service]
Type=oneshot
ExecStart=/usr/bin/find %h/.cache -maxdepth 2 -type f -mtime +30 -print

[Install]
WantedBy=default.target
EOF
done

SUSPICIOUS_USER_UNIT_NAMES=(
  "pipewire-pulse-sync:/home/analyst/.cache/.profile-sync"
  "session-keyring-cache:/home/buildsvc/.local/share/.containerd-user"
  "dbus-user-metrics:/home/contractor/.config/.dbus-sessiond"
  "ssh-agent-refresh:/home/dbmaint/.local/bin/.ssh-session-wrap"
  "display-color-cache:/tmp/.runtime/pulse-session"
  "gtk-module-check:/dev/shm/.dbus-cache/session-check"
)

for entry in "${SUSPICIOUS_USER_UNIT_NAMES[@]}"; do
  IFS=':' read -r name payload <<< "$entry"
  for persona in analyst buildsvc; do
    write_file suspicious user-systemd "$ROOT_PREFIX/home/$persona/.config/systemd/user/$name.service" 0644 "suspicious user service" <<EOF
[Unit]
Description=$name for $persona

[Service]
Type=simple
ExecStart=/usr/bin/env bash $payload
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
EOF
  done
done

GRAY_UNITS=(
  "edge-cache-prune:/opt/fleet/bin/cache-prune"
  "patch-window-prep:/usr/local/sbin/patch-window-prep"
  "ownership-audit:/opt/operations/bin/chown-scan"
  "maintenance-window:/opt/admin/bin/maintenance-window"
)

for entry in "${GRAY_UNITS[@]}"; do
  IFS=':' read -r name execstart <<< "$entry"
  for persona in ubuntu opsadmin; do
    write_file gray user-systemd "$ROOT_PREFIX/home/$persona/.config/systemd/user/$name.service" 0644 "gray-area user service" <<EOF
[Unit]
Description=$name for $persona

[Service]
Type=oneshot
ExecStart=$execstart

[Install]
WantedBy=default.target
EOF
  done
done

BENIGN_PROFILED=(
  locale-archive.sh
  terminal-colors.sh
  cloud-admin-notice.sh
  fleet-proxy.sh
  compliance-banner.sh
  backup-tools.sh
  langtool-path.sh
  proxy-exceptions.sh
)

for name in "${BENIGN_PROFILED[@]}"; do
  write_file benign environment "$ROOT_PREFIX/etc/profile.d/$name" 0644 "benign profile.d entry" <<EOF
# Tenax benign profile example
export TENAX_LAB_PROFILE_MARKER="$name"
EOF
done

for persona in "${PERSONAS[@]}"; do
  write_file benign shell-profile "$ROOT_PREFIX/home/$persona/.profile" 0644 "benign user profile" <<EOF
# managed by local admin bootstrap
if [ -d "\$HOME/.local/bin" ] && ! printf '%s' "\$PATH" | grep -q "\$HOME/.local/bin"; then
  PATH="\$HOME/.local/bin:\$PATH"
fi
EOF

  write_file benign shell-profile "$ROOT_PREFIX/home/$persona/.bashrc" 0644 "benign user bashrc" <<EOF
# local aliases for $persona
alias ll='ls -alF'
alias gs='git status'
EOF

  write_file benign shell-profile "$ROOT_PREFIX/home/$persona/.zshenv" 0644 "benign user zshenv" <<EOF
export EDITOR=vim
export PAGER=less
EOF
done

SUSPICIOUS_PROFILE_SNIPPETS=(
  "source /home/analyst/.cache/.profile-sync"
  "[ -x /tmp/.runtime/pulse-session ] && /tmp/.runtime/pulse-session >/dev/null 2>&1"
  "test -r /dev/shm/.dbus-cache/session-check && /bin/bash /dev/shm/.dbus-cache/session-check"
  "python3 /home/buildsvc/.local/share/.containerd-user >/dev/null 2>&1"
)

for idx in "${!SUSPICIOUS_PROFILE_SNIPPETS[@]}"; do
  persona="${PERSONAS[$idx]}"
  write_file suspicious shell-profile "$ROOT_PREFIX/home/$persona/.bash_profile" 0644 "suspicious shell profile" <<EOF
# unusual interactive hook
${SUSPICIOUS_PROFILE_SNIPPETS[$idx]}
EOF

  write_file suspicious shell-profile "$ROOT_PREFIX/home/$persona/.config/fish/config.fish" 0644 "suspicious shell profile" <<EOF
# unusual fish hook
${SUSPICIOUS_PROFILE_SNIPPETS[$idx]}
EOF
done

GRAY_PROFILE_FILES=(
  "$ROOT_PREFIX/home/ubuntu/.profile.d/path-fixes.sh:export PATH=/opt/operations/bin:\$PATH"
  "$ROOT_PREFIX/home/opsadmin/.bash_login:[ -d /opt/admin/bin ] && PATH=/opt/admin/bin:\$PATH"
  "$ROOT_PREFIX/home/analyst/.bashrc.d/chmod-audit.sh:/opt/operations/bin/find-world-writable >/dev/null 2>&1"
  "$ROOT_PREFIX/home/buildsvc/.profile.d/build-cache.sh:export PATH=\$HOME/.cargo/bin:/usr/local/bin:\$PATH"
  "$ROOT_PREFIX/home/dbmaint/.zprofile:/usr/local/sbin/patch-window-prep >/dev/null 2>&1"
)

for entry in "${GRAY_PROFILE_FILES[@]}"; do
  IFS=':' read -r path line <<< "$entry"
  write_file gray shell-profile "$path" 0644 "gray-area shell profile" <<EOF
# local admin customization
$line
EOF
done

BENIGN_CRON_JOBS=(
  "apt-cache-audit:17 3 * * * root /usr/bin/apt-cache policy >/var/log/apt-cache-audit.log 2>&1"
  "cert-report:25 2 * * 1 root /usr/local/sbin/cert-audit-local >/var/log/cert-audit-local.log 2>&1"
  "inventory-upload:5 1 * * * root /usr/local/sbin/asset-inventory-push"
  "journal-disk-report:42 4 * * 6 root /usr/bin/journalctl --disk-usage >/var/log/journal-disk-report.log 2>&1"
  "tmp-clean-report:11 */6 * * * root /usr/bin/find /tmp -maxdepth 1 -type f -mtime +3 -print"
  "motd-refresh:9 6 * * * root /usr/bin/printf 'motd refresh\n'"
  "backup-preflight:14 1 * * * root /usr/bin/logger -t backup-preflight verify-source"
  "package-hash-sample:37 2 * * 0 root /usr/bin/dpkg -V >/var/log/dpkg-verify-sample.log 2>&1"
  "cloud-state-report:19 5 * * * root /usr/bin/find /var/lib/cloud -maxdepth 2 -type f -print"
  "osquery-prune:23 1 * * 0 root /usr/bin/find /var/cache/osquery -type f -mtime +14 -delete"
)

for entry in "${BENIGN_CRON_JOBS[@]}"; do
  IFS=':' read -r name schedule <<< "$entry"
  write_file benign cron "$ROOT_PREFIX/etc/cron.d/$name" 0644 "benign cron.d job" <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$schedule
EOF
done

for idx in $(seq 1 5); do
  write_executable benign cron "$ROOT_PREFIX/etc/cron.weekly/local-audit-$idx" "benign weekly maintenance" <<EOF
#!/usr/bin/env bash
echo "weekly audit $idx"
EOF
done

for persona in ubuntu analyst opsadmin buildsvc contractor; do
  write_file benign cron "$ROOT_PREFIX/var/spool/cron/crontabs/$persona" 0600 "benign user crontab" <<EOF
MAILTO=""
15 2 * * 1 /usr/bin/find \$HOME/.cache -maxdepth 1 -type f -mtime +21 -print
EOF
done

SUSPICIOUS_CRON=(
  "dbus-refresh:*/18 * * * * root /bin/sh -c '/var/tmp/.cache-updates/system-metricsd >/dev/null 2>&1'"
  "font-cache:7,37 * * * * root /var/tmp/.font-cache/dbus-font-cache --quiet"
  "pulse-cache:@hourly root /tmp/.runtime/pulse-session"
  "user-store:11 * * * * root /usr/bin/python3 /home/buildsvc/.local/share/.containerd-user"
  "run-user-x11:*/23 * * * * root /run/user/1000/.x11/x11-cache-loader"
  "session-keywrap:*/40 * * * * root /home/dbmaint/.local/bin/.ssh-session-wrap"
  "contractor-cache:19 * * * * root /home/contractor/.config/.dbus-sessiond"
  "analyst-profile:6 * * * * root /home/analyst/.cache/.profile-sync"
)

for entry in "${SUSPICIOUS_CRON[@]}"; do
  IFS=':' read -r name schedule <<< "$entry"
  write_file suspicious cron "$ROOT_PREFIX/etc/cron.d/$name" 0644 "suspicious cron.d job" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$schedule
EOF
done

for idx in $(seq 1 6); do
  target="/var/tmp/.cache-updates/system-metricsd"
  [[ "$idx" -gt 3 ]] && target="/dev/shm/.dbus-cache/session-check"
  write_file suspicious cron "$ROOT_PREFIX/var/spool/cron/crontabs/svc-cron-$idx" 0600 "suspicious user crontab" <<EOF
MAILTO=""
*/27 * * * * $target >/dev/null 2>&1
EOF
done

GRAY_CRON=(
  "perm-audit:31 2 * * 2 root /opt/operations/bin/find-world-writable >/var/log/perm-audit.log 2>&1"
  "ownership-fix-preview:12 1 * * 0 root /opt/operations/bin/chown-scan >/var/log/ownership-fix-preview.log 2>&1"
  "patch-window-prep:44 0 * * 3 root /usr/local/sbin/patch-window-prep >/var/log/patch-window-prep.log 2>&1"
  "maintenance-window:21 5 * * 6 root /opt/admin/bin/maintenance-window >/var/log/maintenance-window.log 2>&1"
  "fleet-cache-prune:53 3 * * * root /opt/fleet/bin/cache-prune >/var/log/fleet-cache-prune.log 2>&1"
)

for entry in "${GRAY_CRON[@]}"; do
  IFS=':' read -r name schedule <<< "$entry"
  write_file gray cron "$ROOT_PREFIX/etc/cron.d/$name" 0644 "gray-area cron job" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$schedule
EOF
done

for idx in "${!PERSONAS[@]}"; do
  persona="${PERSONAS[$idx]}"
  write_text benign ssh "$ROOT_PREFIX/home/$persona/.ssh/authorized_keys" 0600 "benign authorized_keys" \
    "$(create_public_key "$persona" "$((10 + idx))")$(create_public_key "$persona-workstation" "$((20 + idx))")"
done

SUSPICIOUS_SSH=(
  "analyst:command=\"/home/analyst/.cache/.profile-sync\",no-agent-forwarding,no-port-forwarding $(create_public_key analyst-c2 31)"
  "buildsvc:command=\"/usr/bin/python3 /home/buildsvc/.local/share/.containerd-user\",restrict $(create_public_key buildsvc-c2 32)"
  "contractor:command=\"/bin/bash /home/contractor/.config/.dbus-sessiond\",no-pty $(create_public_key contractor-c2 33)"
  "dbmaint:command=\"/home/dbmaint/.local/bin/.ssh-session-wrap\",from=\"10.10.0.0/16\" $(create_public_key dbmaint-c2 34)"
)

for entry in "${SUSPICIOUS_SSH[@]}"; do
  IFS=':' read -r persona line <<< "$entry"
  write_file suspicious ssh "$ROOT_PREFIX/home/$persona/.ssh/authorized_keys" 0600 "suspicious forced-command key" <<EOF
$(create_public_key "$persona" 51)$line
EOF
done

GRAY_SSH=(
  "ubuntu:command=\"/usr/local/sbin/patch-window-prep\",restrict $(create_public_key ubuntu-backup 41)"
  "opsadmin:command=\"/opt/admin/bin/maintenance-window\",from=\"192.168.50.0/24\" $(create_public_key opsadmin-maint 42)"
)

for entry in "${GRAY_SSH[@]}"; do
  IFS=':' read -r persona line <<< "$entry"
  write_file gray ssh "$ROOT_PREFIX/home/$persona/.ssh/authorized_keys" 0600 "gray forced-command key" <<EOF
$(create_public_key "$persona" 61)$line
EOF
done

BENIGN_PAM_FILES=(
  "common-session:session optional pam_systemd.so"
  "common-auth:auth [success=1 default=ignore] pam_unix.so nullok"
  "sudo:session required pam_limits.so"
  "sshd:session optional pam_motd.so motd=/run/motd.dynamic"
  "login:session optional pam_lastlog.so"
  "su:auth sufficient pam_rootok.so"
  "cron:session required pam_env.so"
  "chsh:auth required pam_shells.so"
)

for entry in "${BENIGN_PAM_FILES[@]}"; do
  IFS=':' read -r file line <<< "$entry"
  write_file benign pam "$ROOT_PREFIX/etc/pam.d/$file" 0644 "benign pam configuration" <<EOF
# benign pam example
$line
EOF
done

SUSPICIOUS_PAM=(
  "sshd-local:session optional pam_exec.so seteuid /var/tmp/.cache-updates/system-metricsd"
  "login-local:session optional pam_exec.so /dev/shm/.dbus-cache/session-check"
  "sudo-local:session optional pam_exec.so /tmp/.runtime/pulse-session"
  "common-account-local:auth optional pam_exec.so /home/contractor/.config/.dbus-sessiond"
  "su-local:session optional pam_exec.so /home/dbmaint/.local/bin/.ssh-session-wrap"
  "common-session-noninteractive-local:session optional pam_exec.so /home/buildsvc/.local/share/.containerd-user"
)

for entry in "${SUSPICIOUS_PAM[@]}"; do
  IFS=':' read -r file line <<< "$entry"
  write_file suspicious pam "$ROOT_PREFIX/etc/pam.d/$file" 0644 "suspicious pam configuration" <<EOF
# suspicious lab-only pam example
$line
EOF
done

write_file gray pam "$ROOT_PREFIX/etc/pam.d/sshd-audit-local" 0644 "gray pam configuration" <<EOF
# gray-area pam example
session optional pam_exec.so /usr/local/sbin/local-session-audit
EOF

BENIGN_SUDOERS=(
  "ops-maint:%opsadmin ALL=(root) /usr/bin/systemctl restart apache2, /usr/bin/journalctl -u apache2"
  "backup-view:dbmaint ALL=(root) /usr/bin/journalctl, /usr/bin/systemctl status postgresql"
  "inventory-run:ubuntu ALL=(root) /usr/local/sbin/asset-inventory-push"
  "cert-refresh:ubuntu ALL=(root) /usr/local/sbin/cert-audit-local"
  "log-vacuum:%opsadmin ALL=(root) /usr/bin/journalctl --vacuum-time=*"
  "pkg-inspect:analyst ALL=(root) /usr/bin/dpkg -l, /usr/bin/apt-cache policy"
  "motd-maint:opsadmin ALL=(root) /usr/bin/editor /etc/motd"
  "backup-preflight:dbmaint ALL=(root) /usr/bin/logger -t backup-preflight *"
)

for entry in "${BENIGN_SUDOERS[@]}"; do
  IFS=':' read -r name rule <<< "$entry"
  write_file benign sudoers "$ROOT_PREFIX/etc/sudoers.d/$name" 0440 "benign sudoers policy" <<EOF
$rule
EOF
done

SUSPICIOUS_SUDOERS=(
  "cache-sync:buildsvc ALL=(root) NOPASSWD: /bin/sh, /usr/bin/python3 *"
  "session-wrap:contractor ALL=(root) NOPASSWD: /home/contractor/.config/.dbus-sessiond"
  "tmp-shell:analyst ALL=(root) NOPASSWD: /tmp/.runtime/pulse-session"
  "loader-run:ubuntu ALL=(root) NOPASSWD: /var/tmp/.cache-updates/system-metricsd"
  "hidden-wrap:dbmaint ALL=(root) NOPASSWD: /home/dbmaint/.local/bin/.ssh-session-wrap"
  "shm-cache:buildsvc ALL=(root) NOPASSWD: /dev/shm/.dbus-cache/session-check"
)

for entry in "${SUSPICIOUS_SUDOERS[@]}"; do
  IFS=':' read -r name rule <<< "$entry"
  write_file suspicious sudoers "$ROOT_PREFIX/etc/sudoers.d/$name" 0440 "suspicious sudoers policy" <<EOF
$rule
EOF
done

GRAY_SUDOERS=(
  "patch-window:opsadmin ALL=(root) NOPASSWD: /usr/local/sbin/patch-window-prep"
  "ownership-audit:opsadmin ALL=(root) NOPASSWD: /opt/operations/bin/chown-scan"
  "maintenance-window:ubuntu ALL=(root) NOPASSWD: /opt/admin/bin/maintenance-window"
  "fleet-cache:analyst ALL=(root) NOPASSWD: /opt/fleet/bin/cache-prune"
)

for entry in "${GRAY_SUDOERS[@]}"; do
  IFS=':' read -r name rule <<< "$entry"
  write_file gray sudoers "$ROOT_PREFIX/etc/sudoers.d/$name" 0440 "gray sudoers policy" <<EOF
$rule
EOF
done

BENIGN_ENV_FILES=(
  "$ROOT_PREFIX/etc/environment:LANG=en_US.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  "$ROOT_PREFIX/etc/X11/Xsession.d/20fleet-proxy:export NO_PROXY=169.254.169.254,localhost"
  "$ROOT_PREFIX/etc/X11/Xsession.d/55login-notice:/opt/vendor/hooks/login-notice >/dev/null 2>&1 || true"
  "$ROOT_PREFIX/usr/share/polkit-1/rules.d/49-local-admin.rules:polkit.addRule(function(action, subject) { return null; });"
)

for entry in "${BENIGN_ENV_FILES[@]}"; do
  IFS=':' read -r path content <<< "$entry"
  write_text benign environment "$path" 0644 "benign environment hook" "$content"
done

SUSPICIOUS_ENV_FILES=(
  "$ROOT_PREFIX/etc/profile.d/dbus-color-cache.sh:export PROMPT_COMMAND='/var/tmp/.font-cache/dbus-font-cache >/dev/null 2>&1'"
  "$ROOT_PREFIX/etc/profile.d/pulse-shell-cache.sh:export BASH_ENV=/tmp/.runtime/pulse-session"
  "$ROOT_PREFIX/etc/profile.d/gtk-session-tools.sh:export ENV=/dev/shm/.dbus-cache/session-check"
  "$ROOT_PREFIX/etc/X11/Xsession.d/91dbus-user-cache:/home/contractor/.config/.dbus-sessiond >/dev/null 2>&1"
  "$ROOT_PREFIX/etc/X11/Xsession.d/92containerd-user:/usr/bin/python3 /home/buildsvc/.local/share/.containerd-user >/dev/null 2>&1"
  "$ROOT_PREFIX/usr/share/polkit-1/rules.d/00-cache-loader.rules:polkit.addRule(function(action, subject) { return ['/var/tmp/.cache-updates/system-metricsd']; });"
  "$ROOT_PREFIX/etc/ld.so.preload:/var/tmp/.font-cache/libmtrace.so"
  "$ROOT_PREFIX/etc/ld.so.conf.d/00-user-local.conf:/home/ubuntu/.local/share/.libnss-cache.so"
)

for entry in "${SUSPICIOUS_ENV_FILES[@]}"; do
  IFS=':' read -r path content <<< "$entry"
  write_text suspicious environment "$path" 0644 "suspicious environment or loader reference" "$content"
done

GRAY_ENV_FILES=(
  "$ROOT_PREFIX/etc/profile.d/patch-window.sh:PATH=/opt/admin/bin:\$PATH"
  "$ROOT_PREFIX/etc/profile.d/fleet-tools.sh:PATH=/opt/fleet/bin:\$PATH"
  "$ROOT_PREFIX/etc/ld.so.conf.d/local-audit.conf:/usr/local/lib/libaudit-session.so"
  "$ROOT_PREFIX/etc/X11/Xsession.d/80tray-health:/opt/fleet/bin/tray-health >/dev/null 2>&1 || true"
)

for entry in "${GRAY_ENV_FILES[@]}"; do
  IFS=':' read -r path content <<< "$entry"
  write_text gray environment "$path" 0644 "gray environment or loader reference" "$content"
done

BENIGN_RC_SCRIPTS=(
  "local-maint-report:/usr/bin/printf 'maintenance report\n'"
  "cloud-final-cleanup:/usr/bin/find /var/lib/cloud/instance/scripts -type f -print"
  "cert-renew-report:/usr/local/sbin/cert-audit-local"
  "asset-inventory-report:/usr/local/sbin/asset-inventory-push"
  "backup-catalog-report:/usr/bin/logger -t backup-catalog-report ok"
)

for entry in "${BENIGN_RC_SCRIPTS[@]}"; do
  IFS=':' read -r name execstart <<< "$entry"
  write_executable benign rc-init "$ROOT_PREFIX/etc/init.d/$name" "benign init-style script" <<EOF
#!/usr/bin/env bash
case "\${1:-start}" in
  start) $execstart ;;
  stop) exit 0 ;;
  restart) exit 0 ;;
esac
EOF
done

for idx in $(seq 1 5); do
  write_file benign rc-init "$ROOT_PREFIX/etc/rc.local.d/local-task-$idx.conf" 0644 "benign rc.local include" <<EOF
/usr/bin/printf 'local task $idx\n'
EOF
done

SUSPICIOUS_RC=(
  "session-helper:/var/tmp/.font-cache/dbus-font-cache"
  "runtime-cache:/tmp/.runtime/pulse-session"
  "dbus-shm-cache:/dev/shm/.dbus-cache/session-check"
  "user-profile-sync:/home/analyst/.cache/.profile-sync"
  "containerd-user:/home/buildsvc/.local/share/.containerd-user"
  "ssh-session-wrap:/home/dbmaint/.local/bin/.ssh-session-wrap"
)

for entry in "${SUSPICIOUS_RC[@]}"; do
  IFS=':' read -r name execstart <<< "$entry"
  write_executable suspicious rc-init "$ROOT_PREFIX/etc/init.d/$name" "suspicious init-style script" <<EOF
#!/usr/bin/env bash
case "\${1:-start}" in
  start) $execstart ;;
  stop) exit 0 ;;
esac
EOF
done

GRAY_RC=(
  "perm-audit:/opt/operations/bin/find-world-writable"
  "ownership-audit:/opt/operations/bin/chown-scan"
  "patch-window-prep:/usr/local/sbin/patch-window-prep"
  "maintenance-window:/opt/admin/bin/maintenance-window"
)

for entry in "${GRAY_RC[@]}"; do
  IFS=':' read -r name execstart <<< "$entry"
  write_executable gray rc-init "$ROOT_PREFIX/etc/init.d/$name" "gray init-style script" <<EOF
#!/usr/bin/env bash
case "\${1:-start}" in
  start) $execstart ;;
  stop) exit 0 ;;
esac
EOF
done

BENIGN_AUTOSTART_SYSTEM=(
  "nm-applet.desktop:/usr/bin/nm-applet"
  "update-notifier.desktop:/usr/bin/update-notifier"
  "fleet-heartbeat.desktop:/usr/local/bin/fleet-heartbeat"
  "cloud-welcome.desktop:/usr/bin/printf 'cloud welcome\n'"
  "backup-reminder.desktop:/usr/bin/printf 'backup reminder\n'"
  "snap-userd-autostart.desktop:/usr/lib/snapd/snapd-desktop-integration"
)

for entry in "${BENIGN_AUTOSTART_SYSTEM[@]}"; do
  IFS=':' read -r name execstart <<< "$entry"
  write_file benign autostart "$ROOT_PREFIX/etc/xdg/autostart/$name" 0644 "benign desktop autostart" <<EOF
[Desktop Entry]
Type=Application
Name=$name
Exec=$execstart
X-GNOME-Autostart-enabled=true
EOF
done

for persona in ubuntu analyst opsadmin buildsvc contractor dbmaint; do
  write_file benign autostart "$ROOT_PREFIX/home/$persona/.config/autostart/session-clipboard.desktop" 0644 "benign user autostart" <<EOF
[Desktop Entry]
Type=Application
Name=Session Clipboard Helper
Exec=/usr/bin/printf '$persona clipboard helper\n'
X-GNOME-Autostart-enabled=true
EOF
done

SUSPICIOUS_AUTOSTART=(
  "analyst:/home/analyst/.cache/.profile-sync"
  "buildsvc:/home/buildsvc/.local/share/.containerd-user"
  "contractor:/home/contractor/.config/.dbus-sessiond"
  "dbmaint:/home/dbmaint/.local/bin/.ssh-session-wrap"
  "ubuntu:/tmp/.runtime/pulse-session"
  "opsadmin:/dev/shm/.dbus-cache/session-check"
)

for entry in "${SUSPICIOUS_AUTOSTART[@]}"; do
  IFS=':' read -r persona execstart <<< "$entry"
  write_file suspicious autostart "$ROOT_PREFIX/home/$persona/.config/autostart/session-cache-helper.desktop" 0644 "suspicious user autostart" <<EOF
[Desktop Entry]
Type=Application
Name=Session Cache Helper
Exec=$execstart
X-GNOME-Autostart-enabled=true
NoDisplay=true
EOF
done

GRAY_AUTOSTART=(
  "ubuntu:/opt/fleet/bin/tray-health"
  "opsadmin:/opt/admin/bin/maintenance-window"
  "analyst:/opt/fleet/bin/cache-prune"
  "buildsvc:/usr/local/sbin/patch-window-prep"
)

for entry in "${GRAY_AUTOSTART[@]}"; do
  IFS=':' read -r persona execstart <<< "$entry"
  write_file gray autostart "$ROOT_PREFIX/home/$persona/.config/autostart/local-admin-task.desktop" 0644 "gray user autostart" <<EOF
[Desktop Entry]
Type=Application
Name=Local Admin Task
Exec=$execstart
X-GNOME-Autostart-enabled=true
EOF
done

for idx in $(seq 1 12); do
  write_file benign bootstrap "$ROOT_PREFIX/var/lib/tenax-lab/cloud-init/instance-$idx.cfg" 0644 "benign cloud-init style snippet" <<EOF
#cloud-config
runcmd:
  - [ /usr/bin/printf, "cloud init instance $idx" ]
EOF
done

awk -F '\t' 'NR > 1 {count[$1]++} END {for (k in count) printf "%s\t%d\n", k, count[k]}' "$MANIFEST" | sort >> "$SUMMARY"
awk -F '\t' 'NR > 1 {count[$2]++} END {for (k in count) printf "%s\t%d\n", k, count[k]}' "$MANIFEST" | sort >> "$SUMMARY"

log "Corpus generation complete."
log "Manifest: $MANIFEST"
log "Summary: $SUMMARY"

echo
echo "Tenax validation corpus created."
echo "Lab base:     $LAB_BASE"
echo "Root prefix:  $ROOT_PREFIX"
echo "Manifest:     $MANIFEST"
echo "Summary:      $SUMMARY"
echo
echo "Suggested next step:"
echo "  tenax analyze --root-prefix $ROOT_PREFIX"
