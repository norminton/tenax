#!/usr/bin/env bash
set -euo pipefail

LAB_BASE="${LAB_BASE:-/opt/tenax-lab-v2}"
ROOT_PREFIX="${ROOT_PREFIX:-$LAB_BASE/rootfs}"
LOG_DIR="$LAB_BASE/log"
MANIFEST="$LAB_BASE/manifest.tsv"
SUMMARY="$LOG_DIR/summary.txt"
MARKER="$LAB_BASE/CREATED_BY_TENAX_VALIDATION_V2"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

if [[ -d "$ROOT_PREFIX" ]]; then
  case "$ROOT_PREFIX" in
    "$LAB_BASE"/*) rm -rf -- "$ROOT_PREFIX" ;;
    *) echo "Refusing to remove unexpected ROOT_PREFIX: $ROOT_PREFIX" >&2; exit 1 ;;
  esac
fi

mkdir -p "$ROOT_PREFIX" "$LOG_DIR"
: > "$MANIFEST"
: > "$SUMMARY"
printf 'class\tcategory\tpath\tnote\n' >> "$MANIFEST"
printf 'LAB_BASE=%s\nROOT_PREFIX=%s\n' "$LAB_BASE" "$ROOT_PREFIX" > "$MARKER"

register() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$MANIFEST"
}

mkfile() {
  local cls="$1" cat="$2" path="$3" mode="$4" note="$5"
  mkdir -p "$(dirname "$path")"
  cat > "$path"
  chmod "$mode" "$path"
  register "$cls" "$cat" "$path" "$note"
}

mktext() {
  local cls="$1" cat="$2" path="$3" mode="$4" note="$5" content="$6"
  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$content" > "$path"
  chmod "$mode" "$path"
  register "$cls" "$cat" "$path" "$note"
}

mkexec() {
  mkfile "$1" "$2" "$3" 0755 "$4"
}

payload() {
  local path="$1" label="$2"
  mkexec payload payload "$path" "inert placeholder payload" <<EOF
#!/usr/bin/env bash
set -euo pipefail
echo "Tenax validation placeholder: $label"
EOF
}

so_placeholder() {
  local path="$1" label="$2"
  mkfile payload payload "$path" 0644 "inert loader placeholder" <<EOF
PLACEHOLDER ONLY
label=$label
purpose=tenax-validation
EOF
}

pubkey() {
  local tag="$1" num="$2"
  printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPersistLab%02dKeyMaterialOnly %s@tenax-lab\n' "$num" "$tag"
}

PERSONAS=(ubuntu analyst opsadmin appsvc dbadmin devops helpdesk backupsvc)

COMMON_DIRS=(
  "$ROOT_PREFIX/etc/systemd/system"
  "$ROOT_PREFIX/usr/lib/systemd/system"
  "$ROOT_PREFIX/etc/systemd/system/multi-user.target.wants"
  "$ROOT_PREFIX/etc/cron.d"
  "$ROOT_PREFIX/etc/cron.daily"
  "$ROOT_PREFIX/etc/cron.weekly"
  "$ROOT_PREFIX/etc/profile.d"
  "$ROOT_PREFIX/etc/pam.d"
  "$ROOT_PREFIX/etc/security"
  "$ROOT_PREFIX/etc/sudoers.d"
  "$ROOT_PREFIX/etc/init.d"
  "$ROOT_PREFIX/etc/rc.local.d"
  "$ROOT_PREFIX/etc/X11/Xsession.d"
  "$ROOT_PREFIX/etc/xdg/autostart"
  "$ROOT_PREFIX/etc/tmpfiles.d"
  "$ROOT_PREFIX/etc/logrotate.d"
  "$ROOT_PREFIX/etc/default"
  "$ROOT_PREFIX/etc/ld.so.conf.d"
  "$ROOT_PREFIX/usr/local/bin"
  "$ROOT_PREFIX/usr/local/sbin"
  "$ROOT_PREFIX/usr/local/lib"
  "$ROOT_PREFIX/opt/ops/bin"
  "$ROOT_PREFIX/opt/platform/bin"
  "$ROOT_PREFIX/opt/site/bin"
  "$ROOT_PREFIX/var/lib/tenax-lab/payloads"
  "$ROOT_PREFIX/var/lib/site-maint"
  "$ROOT_PREFIX/var/lib/admin-tools"
  "$ROOT_PREFIX/var/tmp/.cache-sync"
  "$ROOT_PREFIX/dev/shm/.x11-cache"
  "$ROOT_PREFIX/tmp/.pulse-meta"
  "$ROOT_PREFIX/run/user/1001/.session"
)

for d in "${COMMON_DIRS[@]}"; do
  mkdir -p "$d"
done

for p in "${PERSONAS[@]}"; do
  mkdir -p \
    "$ROOT_PREFIX/home/$p/.ssh" \
    "$ROOT_PREFIX/home/$p/.config/systemd/user" \
    "$ROOT_PREFIX/home/$p/.config/autostart" \
    "$ROOT_PREFIX/home/$p/.local/bin" \
    "$ROOT_PREFIX/home/$p/.local/share" \
    "$ROOT_PREFIX/home/$p/.cache"
done

payload "$ROOT_PREFIX/var/tmp/.cache-sync/net-policy-sync" "tmp hidden system payload"
payload "$ROOT_PREFIX/dev/shm/.x11-cache/session-audit" "shm hidden payload"
payload "$ROOT_PREFIX/tmp/.pulse-meta/runtime-helper" "tmp hidden payload"
payload "$ROOT_PREFIX/run/user/1001/.session/color-probe" "run-user hidden payload"

for p in analyst appsvc dbadmin devops; do
  payload "$ROOT_PREFIX/home/$p/.cache/.profile-hook" "$p user cache payload"
  payload "$ROOT_PREFIX/home/$p/.local/share/.session-helper" "$p user local-share payload"
  payload "$ROOT_PREFIX/home/$p/.local/bin/.wrap-login" "$p user local-bin payload"
done

so_placeholder "$ROOT_PREFIX/var/tmp/.cache-sync/libnss-stage.so" "tmp preload"
so_placeholder "$ROOT_PREFIX/home/analyst/.local/share/.libdeskcache.so" "user loader ref"
so_placeholder "$ROOT_PREFIX/usr/local/lib/libsiteaudit.so" "gray local audit library"
so_placeholder "$ROOT_PREFIX/usr/local/lib/libjemalloc-local.so" "benign perf library"

for name in \
  rotate-local-logs collect-asset-inventory cert-check-local patch-prep-window \
  backup-preflight pkg-drift-report stale-cache-prune verify-systemd-state \
  motd-refresh-local admin-shell-sanity generate-host-facts prune-build-cache \
  collect-support-bundle check-unit-overrides maintenance-reminder; do
  payload "$ROOT_PREFIX/usr/local/sbin/$name" "benign /usr/local/sbin helper $name"
done

for name in \
  fleet-heartbeat upload-inventory refresh-helpdesk-cache sync-printer-list \
  desktop-theme-fix gather-os-release report-disk-usage verify-cacerts \
  rotate-desktop-cache local-metrics-snapshot support-note-sync repair-path-order \
  cleanup-old-downloads print-login-banner; do
  payload "$ROOT_PREFIX/usr/local/bin/$name" "benign /usr/local/bin helper $name"
done

for name in \
  ops-report-shell ops-prune-archives ops-perm-audit ops-ownership-review \
  platform-cache-audit platform-env-refresh platform-wrapper-check \
  site-maint-window site-backup-scan site-service-report; do
  payload "$ROOT_PREFIX/opt/ops/bin/$name" "gray or benign /opt ops helper $name"
done

BENIGN_SERVICES=(
  "asset-inventory-sync:/usr/local/sbin/collect-asset-inventory"
  "cert-check-local:/usr/local/sbin/cert-check-local"
  "pkg-drift-report:/usr/local/sbin/pkg-drift-report"
  "stale-cache-prune:/usr/local/sbin/stale-cache-prune"
  "verify-systemd-state:/usr/local/sbin/verify-systemd-state"
  "host-facts-refresh:/usr/local/sbin/generate-host-facts"
  "support-bundle-index:/usr/local/sbin/collect-support-bundle"
  "unit-override-audit:/usr/local/sbin/check-unit-overrides"
  "fleet-heartbeat:/usr/local/bin/fleet-heartbeat"
  "inventory-uploader:/usr/local/bin/upload-inventory"
  "disk-usage-report:/usr/local/bin/report-disk-usage"
  "desktop-cache-rotate:/usr/local/bin/rotate-desktop-cache"
  "support-note-sync:/usr/local/bin/support-note-sync"
  "path-order-repair:/usr/local/bin/repair-path-order"
  "ops-report-shell:/opt/ops/bin/ops-report-shell"
  "ops-prune-archives:/opt/ops/bin/ops-prune-archives"
  "ops-perm-audit:/opt/ops/bin/ops-perm-audit"
  "ops-ownership-review:/opt/ops/bin/ops-ownership-review"
  "platform-cache-audit:/opt/ops/bin/platform-cache-audit"
  "platform-env-refresh:/opt/ops/bin/platform-env-refresh"
  "site-maint-window:/opt/ops/bin/site-maint-window"
  "site-backup-scan:/opt/ops/bin/site-backup-scan"
  "site-service-report:/opt/ops/bin/site-service-report"
  "motd-refresh-local:/usr/local/sbin/motd-refresh-local"
)

for entry in "${BENIGN_SERVICES[@]}"; do
  IFS=':' read -r name execstart <<< "$entry"
  mkfile benign systemd "$ROOT_PREFIX/usr/lib/systemd/system/$name.service" 0644 "benign system service" <<EOF
[Unit]
Description=$name
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

for timer in \
  asset-inventory-sync cert-check-local pkg-drift-report stale-cache-prune \
  verify-systemd-state host-facts-refresh support-bundle-index unit-override-audit \
  fleet-heartbeat inventory-uploader disk-usage-report desktop-cache-rotate \
  ops-prune-archives ops-perm-audit platform-cache-audit site-backup-scan; do
  mkfile benign systemd "$ROOT_PREFIX/usr/lib/systemd/system/$timer.timer" 0644 "benign timer" <<EOF
[Unit]
Description=$timer timer

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=20m
Unit=$timer.service

[Install]
WantedBy=timers.target
EOF
done

for svc in ssh.service systemd-timesyncd.service unattended-upgrades.service rsyslog.service apt-daily.service; do
  mkdir -p "$ROOT_PREFIX/etc/systemd/system/$svc.d"
  mkfile benign systemd "$ROOT_PREFIX/etc/systemd/system/$svc.d/10-local-observability.conf" 0644 "benign override drop-in" <<EOF
[Service]
Environment=SYSTEMD_LOG_LEVEL=info
EOF
done

SUSPICIOUS_SERVICES=(
  "netpolicy-cache:/bin/sh -c '/var/tmp/.cache-sync/net-policy-sync --quiet'"
  "session-color-probe:/usr/bin/bash /run/user/1001/.session/color-probe"
  "x11-audit-helper:/usr/bin/env perl /dev/shm/.x11-cache/session-audit"
  "runtime-telemetry-helper:/usr/bin/bash -lc '/tmp/.pulse-meta/runtime-helper'"
  "analyst-profile-cache:/usr/bin/bash /home/analyst/.cache/.profile-hook"
  "analyst-session-helper:/usr/bin/python3 /home/analyst/.local/share/.session-helper"
  "appsvc-login-wrapper:/usr/bin/env sh /home/appsvc/.local/bin/.wrap-login"
  "dbadmin-profile-cache:/usr/bin/bash /home/dbadmin/.cache/.profile-hook"
  "dbadmin-session-helper:/usr/bin/python3 /home/dbadmin/.local/share/.session-helper"
  "devops-login-wrapper:/usr/bin/env sh /home/devops/.local/bin/.wrap-login"
  "motd-runtime-cache:/usr/bin/python3 -c 'import os; os.system(\"/tmp/.pulse-meta/runtime-helper\")'"
  "policy-refresh-wrapper:/usr/bin/nohup /var/tmp/.cache-sync/net-policy-sync"
)

for entry in "${SUSPICIOUS_SERVICES[@]}"; do
  IFS=':' read -r name execstart <<< "$entry"
  mkfile suspicious systemd "$ROOT_PREFIX/etc/systemd/system/$name.service" 0644 "suspicious system service" <<EOF
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

for timer in \
  netpolicy-cache session-color-probe x11-audit-helper runtime-telemetry-helper \
  analyst-profile-cache dbadmin-profile-cache motd-runtime-cache policy-refresh-wrapper; do
  mkfile suspicious systemd "$ROOT_PREFIX/etc/systemd/system/$timer.timer" 0644 "suspicious timer" <<EOF
[Unit]
Description=$timer timer

[Timer]
OnBootSec=7m
OnUnitActiveSec=19m
AccuracySec=1m
Unit=$timer.service

[Install]
WantedBy=timers.target
EOF
done

for p in "${PERSONAS[@]}"; do
  mkfile benign user-systemd "$ROOT_PREFIX/home/$p/.config/systemd/user/session-notes.service" 0644 "benign user service" <<EOF
[Unit]
Description=Session notes sync for $p

[Service]
Type=oneshot
ExecStart=/usr/bin/printf '$p session notes sync\n'

[Install]
WantedBy=default.target
EOF

  mkfile benign user-systemd "$ROOT_PREFIX/home/$p/.config/systemd/user/cache-prune.service" 0644 "benign user service" <<EOF
[Unit]
Description=Cache prune for $p

[Service]
Type=oneshot
ExecStart=/usr/bin/find %h/.cache -maxdepth 2 -type f -mtime +21 -print

[Install]
WantedBy=default.target
EOF
done

declare -A U_PAYLOAD=(
  [analyst]="/home/analyst/.cache/.profile-hook"
  [appsvc]="/home/appsvc/.local/bin/.wrap-login"
  [dbadmin]="/home/dbadmin/.local/share/.session-helper"
  [devops]="/home/devops/.cache/.profile-hook"
)

declare -A U_NAME1=(
  [analyst]="session-color-cache"
  [appsvc]="shell-history-merge"
  [dbadmin]="desktop-state-refresh"
  [devops]="user-notify-bridge"
)

declare -A U_NAME2=(
  [analyst]="interactive-profile-sync"
  [appsvc]="session-wrap-helper"
  [dbadmin]="ui-cache-loader"
  [devops]="login-shell-bridge"
)

for p in analyst appsvc dbadmin devops; do
  mkfile suspicious user-systemd "$ROOT_PREFIX/home/$p/.config/systemd/user/${U_NAME1[$p]}.service" 0644 "suspicious user service" <<EOF
[Unit]
Description=${U_NAME1[$p]} for $p

[Service]
Type=simple
ExecStart=/usr/bin/env bash ${U_PAYLOAD[$p]}
Restart=always
RestartSec=35

[Install]
WantedBy=default.target
EOF

  mkfile suspicious user-systemd "$ROOT_PREFIX/home/$p/.config/systemd/user/${U_NAME2[$p]}.service" 0644 "suspicious user service" <<EOF
[Unit]
Description=${U_NAME2[$p]} for $p

[Service]
Type=simple
ExecStart=${U_PAYLOAD[$p]}
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
EOF
done

for p in ubuntu opsadmin helpdesk backupsvc; do
  mkfile gray user-systemd "$ROOT_PREFIX/home/$p/.config/systemd/user/local-admin-sync.service" 0644 "gray user service" <<EOF
[Unit]
Description=Local admin sync for $p

[Service]
Type=oneshot
ExecStart=/opt/ops/bin/ops-report-shell

[Install]
WantedBy=default.target
EOF
done

PROFILED_CONTENT=(
  "export EDITOR=vim"
  "export PAGER=less"
  "export LESS='-FRX'"
  "export HISTCONTROL=ignoreboth:erasedups"
  "export NO_PROXY=localhost,127.0.0.1,::1,169.254.169.254"
  "umask 022"
  "test -d /usr/local/bin && PATH=/usr/local/bin:\$PATH"
  "test -d \$HOME/.local/bin && PATH=\$HOME/.local/bin:\$PATH"
)

idx=0
for name in \
  locale-defaults pager-defaults history-defaults proxy-defaults editor-defaults \
  local-bin-path site-tools-path shell-safety desktop-defaults less-defaults; do
  line="${PROFILED_CONTENT[$((idx % ${#PROFILED_CONTENT[@]}))]}"
  mkfile benign environment "$ROOT_PREFIX/etc/profile.d/$name.sh" 0644 "benign profile.d entry" <<EOF
# managed locally
$line
EOF
  idx=$((idx + 1))
done

for p in "${PERSONAS[@]}"; do
  mkfile benign shell-profile "$ROOT_PREFIX/home/$p/.profile" 0644 "benign user profile" <<EOF
if [ -d "\$HOME/.local/bin" ]; then
  PATH="\$HOME/.local/bin:\$PATH"
fi
export EDITOR=vim
export PAGER=less
EOF

  mkfile benign shell-profile "$ROOT_PREFIX/home/$p/.bashrc" 0644 "benign user shell rc" <<EOF
alias ll='ls -alF'
export HISTCONTROL=ignoreboth:erasedups
EOF
done

declare -A SP1=(
  [analyst]="source /home/analyst/.cache/.profile-hook"
  [appsvc]="[ -x /home/appsvc/.local/bin/.wrap-login ] && /home/appsvc/.local/bin/.wrap-login >/dev/null 2>&1"
  [dbadmin]="python3 /home/dbadmin/.local/share/.session-helper >/dev/null 2>&1"
  [devops]="test -r /home/devops/.cache/.profile-hook && /bin/bash /home/devops/.cache/.profile-hook"
)

for p in analyst appsvc dbadmin devops; do
  mkfile suspicious shell-profile "$ROOT_PREFIX/home/$p/.bash_profile" 0644 "suspicious shell profile" <<EOF
# local session hook
${SP1[$p]}
EOF
done

mkfile suspicious environment "$ROOT_PREFIX/etc/profile.d/system-shell-env.sh" 0644 "suspicious environment hook" <<EOF
export BASH_ENV=/tmp/.pulse-meta/runtime-helper
EOF

mkfile suspicious environment "$ROOT_PREFIX/etc/profile.d/system-login-env.sh" 0644 "suspicious environment hook" <<EOF
export ENV=/dev/shm/.x11-cache/session-audit
EOF

mkfile suspicious environment "$ROOT_PREFIX/etc/profile.d/system-prompt-cache.sh" 0644 "suspicious environment hook" <<EOF
export PROMPT_COMMAND='/var/tmp/.cache-sync/net-policy-sync >/dev/null 2>&1'
EOF

mkfile gray environment "$ROOT_PREFIX/etc/profile.d/site-admin-tools.sh" 0644 "gray profile.d entry" <<EOF
test -d /opt/ops/bin && PATH=/opt/ops/bin:\$PATH
export NO_PROXY=localhost,127.0.0.1,::1
EOF

mkfile gray environment "$ROOT_PREFIX/etc/default/site-maintenance" 0644 "gray environment file" <<EOF
SITE_MAINT_WINDOW=saturday-0200
SITE_MAINT_WRAPPER=/opt/ops/bin/site-maint-window
EOF

BENIGN_CRON=(
  "asset-inventory:5 1 * * * root /usr/local/sbin/collect-asset-inventory"
  "cert-check:15 2 * * 1 root /usr/local/sbin/cert-check-local"
  "backup-preflight:35 0 * * * root /usr/local/sbin/backup-preflight"
  "pkg-drift:42 3 * * 0 root /usr/local/sbin/pkg-drift-report"
  "desktop-cache:11 */6 * * * root /usr/local/bin/rotate-desktop-cache"
  "support-sync:7 2 * * * root /usr/local/bin/support-note-sync"
  "ops-audit:24 4 * * 6 root /opt/ops/bin/ops-perm-audit"
  "site-backup-scan:18 5 * * * root /opt/ops/bin/site-backup-scan"
)

for entry in "${BENIGN_CRON[@]}"; do
  IFS=':' read -r name rule <<< "$entry"
  mkfile benign cron "$ROOT_PREFIX/etc/cron.d/$name" 0644 "benign cron.d entry" <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$rule
EOF
done

for n in 1 2 3 4 5 6; do
  mkexec benign cron "$ROOT_PREFIX/etc/cron.weekly/local-maint-$n" "benign weekly maintenance" <<EOF
#!/usr/bin/env bash
echo "weekly maintenance $n"
EOF
done

SUSPICIOUS_CRON=(
  "runtime-helper:@hourly root /tmp/.pulse-meta/runtime-helper"
  "cache-sync:17 * * * * root /bin/sh -c '/var/tmp/.cache-sync/net-policy-sync >/dev/null 2>&1'"
  "session-audit:27 * * * * root /dev/shm/.x11-cache/session-audit"
  "analyst-profile:39 * * * * root /home/analyst/.cache/.profile-hook"
  "appsvc-wrap:11 * * * * root /home/appsvc/.local/bin/.wrap-login"
  "dbadmin-session:22 * * * * root /usr/bin/python3 /home/dbadmin/.local/share/.session-helper"
)

for entry in "${SUSPICIOUS_CRON[@]}"; do
  IFS=':' read -r name rule <<< "$entry"
  mkfile suspicious cron "$ROOT_PREFIX/etc/cron.d/$name" 0644 "suspicious cron.d entry" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$rule
EOF
done

GRAY_CRON=(
  "perm-audit-preview:13 2 * * 2 root /opt/ops/bin/ops-perm-audit >/var/log/perm-audit-preview.log 2>&1"
  "ownership-review:41 1 * * 0 root /opt/ops/bin/ops-ownership-review >/var/log/ownership-review.log 2>&1"
  "patch-window:19 0 * * 3 root /usr/local/sbin/patch-prep-window >/var/log/patch-prep-window.log 2>&1"
  "service-report:53 4 * * 6 root /opt/ops/bin/site-service-report >/var/log/site-service-report.log 2>&1"
)

for entry in "${GRAY_CRON[@]}"; do
  IFS=':' read -r name rule <<< "$entry"
  mkfile gray cron "$ROOT_PREFIX/etc/cron.d/$name" 0644 "gray cron entry" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$rule
EOF
done

for i in "${!PERSONAS[@]}"; do
  p="${PERSONAS[$i]}"
  mktext benign ssh "$ROOT_PREFIX/home/$p/.ssh/authorized_keys" 0600 "benign authorized_keys" \
    "$(pubkey "$p" "$((10+i))")
$(pubkey "$p-workstation" "$((20+i))")"
done

mkfile suspicious ssh "$ROOT_PREFIX/home/analyst/.ssh/authorized_keys" 0600 "suspicious forced-command key" <<EOF
command="/home/analyst/.cache/.profile-hook",no-agent-forwarding,no-port-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPersistLab31KeyMaterialOnly analyst-admin@tenax-lab
EOF

mkfile suspicious ssh "$ROOT_PREFIX/home/appsvc/.ssh/authorized_keys" 0600 "suspicious forced-command key" <<EOF
command="/home/appsvc/.local/bin/.wrap-login",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPersistLab32KeyMaterialOnly appsvc-batch@tenax-lab
EOF

mkfile suspicious ssh "$ROOT_PREFIX/home/dbadmin/.ssh/authorized_keys" 0600 "suspicious forced-command key" <<EOF
command="/usr/bin/python3 /home/dbadmin/.local/share/.session-helper",from="10.10.0.0/16" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPersistLab33KeyMaterialOnly dbadmin-job@tenax-lab
EOF

mkfile gray ssh "$ROOT_PREFIX/home/opsadmin/.ssh/authorized_keys" 0600 "gray forced-command key" <<EOF
command="/usr/local/sbin/patch-prep-window",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPersistLab34KeyMaterialOnly opsadmin-maint@tenax-lab
EOF

BENIGN_PAM=(
  "common-session:session optional pam_systemd.so"
  "common-auth:auth [success=1 default=ignore] pam_unix.so nullok"
  "sudo:session required pam_limits.so"
  "sshd:session optional pam_motd.so motd=/run/motd.dynamic"
  "login:session optional pam_lastlog.so"
  "cron:session required pam_env.so"
)

for entry in "${BENIGN_PAM[@]}"; do
  IFS=':' read -r file line <<< "$entry"
  mkfile benign pam "$ROOT_PREFIX/etc/pam.d/$file" 0644 "benign pam file" <<EOF
#line maintained locally
$line
EOF
done

SUSPICIOUS_PAM=(
  "sshd-local:session optional pam_exec.so seteuid /var/tmp/.cache-sync/net-policy-sync"
  "login-local:session optional pam_exec.so /dev/shm/.x11-cache/session-audit"
  "sudo-local:session optional pam_exec.so /tmp/.pulse-meta/runtime-helper"
  "appsvc-local:session optional pam_exec.so /home/appsvc/.local/bin/.wrap-login"
  "dbadmin-local:session optional pam_exec.so /home/dbadmin/.local/share/.session-helper"
)

for entry in "${SUSPICIOUS_PAM[@]}"; do
  IFS=':' read -r file line <<< "$entry"
  mkfile suspicious pam "$ROOT_PREFIX/etc/pam.d/$file" 0644 "suspicious pam file" <<EOF
# validation corpus
$line
EOF
done

mkfile gray pam "$ROOT_PREFIX/etc/pam.d/ops-audit-local" 0644 "gray pam file" <<EOF
session optional pam_exec.so /usr/local/sbin/admin-shell-sanity
EOF

mkfile gray pam "$ROOT_PREFIX/etc/security/access-local-admin.conf" 0644 "gray PAM-adjacent config" <<EOF
# local access policy notes
# helpdesk and opsadmin may use console during maintenance windows
EOF

for entry in \
  "ops-maint:%opsadmin ALL=(root) /usr/bin/systemctl restart apache2, /usr/bin/journalctl -u apache2" \
  "db-view:dbadmin ALL=(root) /usr/bin/journalctl, /usr/bin/systemctl status postgresql" \
  "inv-run:ubuntu ALL=(root) /usr/local/sbin/collect-asset-inventory" \
  "cert-run:ubuntu ALL=(root) /usr/local/sbin/cert-check-local" \
  "backup-preflight:backupsvc ALL=(root) /usr/local/sbin/backup-preflight" \
  "host-facts:helpdesk ALL=(root) /usr/local/sbin/generate-host-facts"; do
  IFS=':' read -r name rule <<< "$entry"
  mkfile benign sudoers "$ROOT_PREFIX/etc/sudoers.d/$name" 0440 "benign sudoers include" <<EOF
$rule
EOF
done

for entry in \
  "cache-sync:appsvc ALL=(root) NOPASSWD: /home/appsvc/.local/bin/.wrap-login" \
  "tmp-helper:ubuntu ALL=(root) NOPASSWD: /tmp/.pulse-meta/runtime-helper" \
  "db-session:dbadmin ALL=(root) NOPASSWD: /usr/bin/python3 /home/dbadmin/.local/share/.session-helper" \
  "netpolicy:opsadmin ALL=(root) NOPASSWD: /var/tmp/.cache-sync/net-policy-sync"; do
  IFS=':' read -r name rule <<< "$entry"
  mkfile suspicious sudoers "$ROOT_PREFIX/etc/sudoers.d/$name" 0440 "suspicious sudoers include" <<EOF
$rule
EOF
done

for entry in \
  "patch-window:opsadmin ALL=(root) NOPASSWD: /usr/local/sbin/patch-prep-window" \
  "perm-audit:opsadmin ALL=(root) NOPASSWD: /opt/ops/bin/ops-perm-audit" \
  "ownership-review:opsadmin ALL=(root) NOPASSWD: /opt/ops/bin/ops-ownership-review" \
  "site-maint:helpdesk ALL=(root) NOPASSWD: /opt/ops/bin/site-maint-window"; do
  IFS=':' read -r name rule <<< "$entry"
  mkfile gray sudoers "$ROOT_PREFIX/etc/sudoers.d/$name" 0440 "gray sudoers include" <<EOF
$rule
EOF
done

mkfile benign environment "$ROOT_PREFIX/etc/X11/Xsession.d/50-local-proxy" 0644 "benign Xsession hook" <<EOF
export NO_PROXY=localhost,127.0.0.1,::1,169.254.169.254
EOF

mkfile benign environment "$ROOT_PREFIX/etc/ld.so.conf.d/local-audit.conf" 0644 "gray-benign loader config" <<EOF
/usr/local/lib/libsiteaudit.so
EOF

mkfile suspicious environment "$ROOT_PREFIX/etc/ld.so.preload" 0644 "suspicious loader reference" <<EOF
/var/tmp/.cache-sync/libnss-stage.so
EOF

mkfile suspicious environment "$ROOT_PREFIX/etc/ld.so.conf.d/user-local.conf" 0644 "suspicious loader reference" <<EOF
/home/analyst/.local/share/.libdeskcache.so
EOF

for entry in \
  "host-maint-report:/usr/local/sbin/verify-systemd-state" \
  "support-bundle-index:/usr/local/sbin/collect-support-bundle" \
  "motd-refresh:/usr/local/sbin/motd-refresh-local"; do
  IFS=':' read -r name cmd <<< "$entry"
  mkexec benign rc-init "$ROOT_PREFIX/etc/init.d/$name" "benign init-style script" <<EOF
#!/usr/bin/env bash
case "\${1:-start}" in
  start) $cmd ;;
  stop) exit 0 ;;
esac
EOF
done

for entry in \
  "runtime-helper:/tmp/.pulse-meta/runtime-helper" \
  "session-audit:/dev/shm/.x11-cache/session-audit" \
  "analyst-profile:/home/analyst/.cache/.profile-hook"; do
  IFS=':' read -r name cmd <<< "$entry"
  mkexec suspicious rc-init "$ROOT_PREFIX/etc/init.d/$name" "suspicious init-style script" <<EOF
#!/usr/bin/env bash
case "\${1:-start}" in
  start) $cmd ;;
  stop) exit 0 ;;
esac
EOF
done

for entry in \
  "nm-applet.desktop:/usr/bin/nm-applet" \
  "update-notifier.desktop:/usr/bin/update-notifier" \
  "fleet-heartbeat.desktop:/usr/local/bin/fleet-heartbeat" \
  "support-note-sync.desktop:/usr/local/bin/support-note-sync"; do
  IFS=':' read -r name execstart <<< "$entry"
  mkfile benign autostart "$ROOT_PREFIX/etc/xdg/autostart/$name" 0644 "benign desktop autostart" <<EOF
[Desktop Entry]
Type=Application
Name=$name
Exec=$execstart
X-GNOME-Autostart-enabled=true
EOF
done

for p in analyst appsvc dbadmin devops; do
  local_exec="/home/$p/.cache/.profile-hook"
  [[ "$p" == "appsvc" ]] && local_exec="/home/$p/.local/bin/.wrap-login"
  [[ "$p" == "dbadmin" ]] && local_exec="/home/$p/.local/share/.session-helper"
  mkfile suspicious autostart "$ROOT_PREFIX/home/$p/.config/autostart/session-cache-helper.desktop" 0644 "suspicious user autostart" <<EOF
[Desktop Entry]
Type=Application
Name=Session Cache Helper
Exec=$local_exec
X-GNOME-Autostart-enabled=true
NoDisplay=true
EOF
done

for p in ubuntu opsadmin helpdesk backupsvc; do
  mkfile gray autostart "$ROOT_PREFIX/home/$p/.config/autostart/local-admin-task.desktop" 0644 "gray user autostart" <<EOF
[Desktop Entry]
Type=Application
Name=Local Admin Task
Exec=/opt/ops/bin/site-maint-window
X-GNOME-Autostart-enabled=true
EOF
done

for n in $(seq 1 12); do
  mkfile benign bootstrap "$ROOT_PREFIX/var/lib/site-maint/cloud-$n.cfg" 0644 "benign cloud/bootstrap snippet" <<EOF
#cloud-config
runcmd:
  - [ /usr/bin/printf, "site maintenance snippet $n" ]
EOF
done

awk -F '\t' 'NR>1{c[$1]++} END{for(k in c) print k "\t" c[k]}' "$MANIFEST" | sort > "$SUMMARY"
awk -F '\t' 'NR>1{c[$2]++} END{for(k in c) print k "\t" c[k]}' "$MANIFEST" | sort >> "$SUMMARY"

echo "Created refined Tenax validation corpus at $ROOT_PREFIX"
echo "Manifest: $MANIFEST"
echo "Summary: $SUMMARY"
echo "Suggested analysis: tenax analyze --root-prefix $ROOT_PREFIX"
