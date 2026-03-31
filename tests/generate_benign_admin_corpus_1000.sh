#!/usr/bin/env bash
set -euo pipefail

LAB_BASE="${LAB_BASE:-/opt/tenax-benign1000}"
ROOT_PREFIX="${ROOT_PREFIX:-$LAB_BASE/rootfs}"
LOG_DIR="$LAB_BASE/log"
MANIFEST="$LAB_BASE/manifest.tsv"
SUMMARY="$LOG_DIR/summary.txt"
MARKER="$LAB_BASE/CREATED_BY_TENAX_BENIGN_1000"

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
printf 'category\tpath\tnote\n' >> "$MANIFEST"
printf 'LAB_BASE=%s\nROOT_PREFIX=%s\n' "$LAB_BASE" "$ROOT_PREFIX" > "$MARKER"

record() {
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$MANIFEST"
}

mkfile() {
  local cat="$1" path="$2" mode="$3" note="$4"
  mkdir -p "$(dirname "$path")"
  cat > "$path"
  chmod "$mode" "$path"
  record "$cat" "$path" "$note"
}

mktext() {
  local cat="$1" path="$2" mode="$3" note="$4" content="$5"
  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$content" > "$path"
  chmod "$mode" "$path"
  record "$cat" "$path" "$note"
}

mkexec() {
  mkfile "$1" "$2" 0755 "$3"
}

PERSONAS=(ubuntu analyst opsadmin appsvc dbadmin devops helpdesk backupsvc secops qa release)
SERVICE_VERBS=(collect rotate sync report refresh prune verify index reconcile stage audit repair clean validate snapshot inspect)
SERVICE_NOUNS=(inventory cache logs certs packages metrics desktop backups sessions journals archives paths units support facts accounts printers)
TIMER_CAL=(daily weekly monthly)
PROFILE_LINES=(
  "export EDITOR=vim"
  "export PAGER=less"
  "export LESS='-FRX'"
  "export HISTCONTROL=ignoreboth:erasedups"
  "export NO_PROXY=localhost,127.0.0.1,::1,169.254.169.254"
  "umask 022"
  "test -d /usr/local/bin && PATH=/usr/local/bin:\$PATH"
  "test -d \$HOME/.local/bin && PATH=\$HOME/.local/bin:\$PATH"
)
SUDO_CMDS=(
  "/usr/bin/systemctl status apache2"
  "/usr/bin/systemctl status ssh"
  "/usr/bin/journalctl -u rsyslog"
  "/usr/bin/journalctl -u cron"
  "/usr/bin/dpkg -l"
  "/usr/bin/apt-cache policy"
  "/usr/bin/find /var/log -maxdepth 1 -type f -print"
)
ENV_NAMES=(SITE_REGION HELP_DESK_QUEUE ASSET_TAG_PREFIX PROXY_DOMAIN PATCH_WINDOW MONITORING_SITE BACKUP_POLICY DESKTOP_THEME)
ENV_VALS=(iad-1 localops corp.example saturday-0200 bronze standard blue weekly)

COMMON_DIRS=(
  "$ROOT_PREFIX/usr/lib/systemd/system"
  "$ROOT_PREFIX/etc/systemd/system"
  "$ROOT_PREFIX/etc/systemd/system/ssh.service.d"
  "$ROOT_PREFIX/etc/systemd/system/cron.service.d"
  "$ROOT_PREFIX/etc/profile.d"
  "$ROOT_PREFIX/usr/local/bin"
  "$ROOT_PREFIX/usr/local/sbin"
  "$ROOT_PREFIX/opt/ops/bin"
  "$ROOT_PREFIX/opt/platform/bin"
  "$ROOT_PREFIX/opt/support/bin"
  "$ROOT_PREFIX/etc/logrotate.d"
  "$ROOT_PREFIX/etc/cron.d"
  "$ROOT_PREFIX/etc/cron.daily"
  "$ROOT_PREFIX/etc/cron.weekly"
  "$ROOT_PREFIX/etc/sudoers.d"
  "$ROOT_PREFIX/etc/pam.d"
  "$ROOT_PREFIX/etc/security"
  "$ROOT_PREFIX/etc/default"
  "$ROOT_PREFIX/etc/tmpfiles.d"
  "$ROOT_PREFIX/etc/sysctl.d"
  "$ROOT_PREFIX/etc/modprobe.d"
  "$ROOT_PREFIX/etc/xdg/autostart"
  "$ROOT_PREFIX/var/lib/cloud/scripts/per-instance"
  "$ROOT_PREFIX/var/lib/site-admin"
  "$ROOT_PREFIX/etc/monitoring"
)

for d in "${COMMON_DIRS[@]}"; do mkdir -p "$d"; done

for p in "${PERSONAS[@]}"; do
  mkdir -p \
    "$ROOT_PREFIX/home/$p/.config/systemd/user" \
    "$ROOT_PREFIX/home/$p/.config/autostart" \
    "$ROOT_PREFIX/home/$p/.local/bin" \
    "$ROOT_PREFIX/home/$p/.cache"
done

count=0

for i in $(seq 1 100); do
  verb="${SERVICE_VERBS[$(((i-1) % ${#SERVICE_VERBS[@]}))]}"
  noun="${SERVICE_NOUNS[$(((i+2) % ${#SERVICE_NOUNS[@]}))]}"
  exec="/usr/local/sbin/${verb}-${noun}-${i}"
  mkexec systemd-service "$ROOT_PREFIX$exec" "benign system helper" <<EOF
#!/usr/bin/env bash
echo "${verb} ${noun} job $i"
EOF
  mkfile systemd-service "$ROOT_PREFIX/usr/lib/systemd/system/${verb}-${noun}-${i}.service" 0644 "benign systemd service" <<EOF
[Unit]
Description=${verb}-${noun}-${i}
After=network-online.target

[Service]
Type=oneshot
ExecStart=$exec

[Install]
WantedBy=multi-user.target
EOF
  count=$((count + 1))
done

for i in $(seq 1 70); do
  verb="${SERVICE_VERBS[$(((i+3) % ${#SERVICE_VERBS[@]}))]}"
  noun="${SERVICE_NOUNS[$(((i+5) % ${#SERVICE_NOUNS[@]}))]}"
  cal="${TIMER_CAL[$(((i-1) % ${#TIMER_CAL[@]}))]}"
  mkfile systemd-timer "$ROOT_PREFIX/usr/lib/systemd/system/${verb}-${noun}-${i}.timer" 0644 "benign timer" <<EOF
[Unit]
Description=${verb}-${noun}-${i} timer

[Timer]
OnCalendar=$cal
Persistent=true
RandomizedDelaySec=15m
Unit=${verb}-${noun}-${i}.service

[Install]
WantedBy=timers.target
EOF
  count=$((count + 1))
done

for i in $(seq 1 70); do
  base=$([[ $((i % 2)) -eq 0 ]] && echo "ssh.service" || echo "cron.service")
  mkdir -p "$ROOT_PREFIX/etc/systemd/system/$base.d"
  mkfile systemd-dropin "$ROOT_PREFIX/etc/systemd/system/$base.d/10-local-$i.conf" 0644 "benign drop-in" <<EOF
[Service]
Environment=LOCAL_AUDIT_TAG=site-$i
EOF
  count=$((count + 1))
done

for i in $(seq 1 80); do
  line="${PROFILE_LINES[$(((i-1) % ${#PROFILE_LINES[@]}))]}"
  mkfile profiled "$ROOT_PREFIX/etc/profile.d/site-default-$i.sh" 0644 "benign profile.d script" <<EOF
# local admin defaults
$line
EOF
  count=$((count + 1))
done

for i in $(seq 1 90); do
  bin=$([[ $((i % 2)) -eq 0 ]] && echo "/usr/local/bin" || echo "/usr/local/sbin")
  verb="${SERVICE_VERBS[$(((i+7) % ${#SERVICE_VERBS[@]}))]}"
  noun="${SERVICE_NOUNS[$(((i+11) % ${#SERVICE_NOUNS[@]}))]}"
  mkexec local-wrapper "$ROOT_PREFIX$bin/${verb}-${noun}-wrapper-$i" "benign local wrapper" <<EOF
#!/usr/bin/env bash
echo "${verb} ${noun} wrapper $i"
EOF
  count=$((count + 1))
done

for i in $(seq 1 70); do
  base=$([[ $((i % 3)) -eq 0 ]] && echo "/opt/platform/bin" || ([[ $((i % 2)) -eq 0 ]] && echo "/opt/support/bin" || echo "/opt/ops/bin"))
  verb="${SERVICE_VERBS[$(((i+2) % ${#SERVICE_VERBS[@]}))]}"
  noun="${SERVICE_NOUNS[$(((i+9) % ${#SERVICE_NOUNS[@]}))]}"
  mkexec opt-wrapper "$ROOT_PREFIX$base/${verb}-${noun}-tool-$i" "benign /opt admin wrapper" <<EOF
#!/usr/bin/env bash
echo "${verb} ${noun} tool $i"
EOF
  count=$((count + 1))
done

for i in $(seq 1 70); do
  mkfile logrotate "$ROOT_PREFIX/etc/logrotate.d/site-logs-$i" 0644 "benign logrotate snippet" <<EOF
/var/log/site-admin/log-$i.log {
    rotate 7
    daily
    missingok
    notifempty
    compress
}
EOF
  count=$((count + 1))
done

for i in $(seq 1 35); do
  mkfile cron "$ROOT_PREFIX/etc/cron.d/site-cron-$i" 0644 "benign cron.d entry" <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$((i % 59)) $((i % 6)) * * * root /usr/local/sbin/rotate-logs-wrapper-$(( (i % 20) + 1 ))
EOF
  count=$((count + 1))
done

for i in $(seq 1 20); do
  mkexec cron "$ROOT_PREFIX/etc/cron.daily/local-maint-$i" "benign cron.daily script" <<EOF
#!/usr/bin/env bash
echo "daily maintenance $i"
EOF
  count=$((count + 1))
done

for i in $(seq 1 15); do
  mkexec cron "$ROOT_PREFIX/etc/cron.weekly/local-audit-$i" "benign cron.weekly script" <<EOF
#!/usr/bin/env bash
echo "weekly audit $i"
EOF
  count=$((count + 1))
done

for i in $(seq 1 55); do
  mkexec maintenance "$ROOT_PREFIX/var/lib/site-admin/maintenance-$i.sh" "benign maintenance script" <<EOF
#!/usr/bin/env bash
echo "maintenance task $i"
EOF
  count=$((count + 1))
done

for i in $(seq 1 55); do
  p="${PERSONAS[$(((i-1) % ${#PERSONAS[@]}))]}"
  mkfile user-service "$ROOT_PREFIX/home/$p/.config/systemd/user/user-helper-$i.service" 0644 "benign user helper service" <<EOF
[Unit]
Description=user-helper-$i for $p

[Service]
Type=oneshot
ExecStart=/usr/bin/printf '$p helper $i\n'

[Install]
WantedBy=default.target
EOF
  count=$((count + 1))
done

for i in $(seq 1 45); do
  p="${PERSONAS[$(((i+2) % ${#PERSONAS[@]}))]}"
  mkfile autostart "$ROOT_PREFIX/home/$p/.config/autostart/desktop-helper-$i.desktop" 0644 "benign user autostart" <<EOF
[Desktop Entry]
Type=Application
Name=Desktop Helper $i
Exec=/usr/bin/printf 'desktop helper $i\n'
X-GNOME-Autostart-enabled=true
EOF
  count=$((count + 1))
done

for i in $(seq 1 35); do
  p="${PERSONAS[$(((i+1) % ${#PERSONAS[@]}))]}"
  cmd="${SUDO_CMDS[$(((i-1) % ${#SUDO_CMDS[@]}))]}"
  mkfile sudoers "$ROOT_PREFIX/etc/sudoers.d/site-admin-$i" 0440 "benign sudoers include" <<EOF
$p ALL=(root) $cmd
EOF
  count=$((count + 1))
done

for i in $(seq 1 10); do
  mkfile pam "$ROOT_PREFIX/etc/pam.d/local-login-note-$i" 0644 "benign PAM config" <<EOF
# local note $i
session optional pam_motd.so motd=/run/motd.dynamic
EOF
  count=$((count + 1))
done

for i in $(seq 1 10); do
  mkfile pam "$ROOT_PREFIX/etc/security/access-local-$i.conf" 0644 "benign access policy note" <<EOF
# maintenance access policy note $i
# helpdesk may use console during approved windows
EOF
  count=$((count + 1))
done

for i in $(seq 1 35); do
  name="${ENV_NAMES[$(((i-1) % ${#ENV_NAMES[@]}))]}"
  val="${ENV_VALS[$(((i+3) % ${#ENV_VALS[@]}))]}"
  mkfile environment "$ROOT_PREFIX/etc/default/site-env-$i" 0644 "benign environment file" <<EOF
$name=$val
EOF
  count=$((count + 1))
done

for i in $(seq 1 25); do
  mkfile tmpfiles "$ROOT_PREFIX/etc/tmpfiles.d/site-cache-$i.conf" 0644 "benign tmpfiles snippet" <<EOF
d /var/cache/site-admin-$i 0755 root root -
EOF
  count=$((count + 1))
done

for i in $(seq 1 15); do
  mkfile sysctl "$ROOT_PREFIX/etc/sysctl.d/60-site-$i.conf" 0644 "benign sysctl fragment" <<EOF
# local tuning note $i
vm.swappiness=10
EOF
  count=$((count + 1))
done

for i in $(seq 1 15); do
  mkfile modprobe "$ROOT_PREFIX/etc/modprobe.d/local-hardware-$i.conf" 0644 "benign modprobe snippet" <<EOF
# local hardware preference $i
options snd_hda_intel power_save=1
EOF
  count=$((count + 1))
done

for i in $(seq 1 20); do
  mkfile cloud "$ROOT_PREFIX/var/lib/cloud/scripts/per-instance/site-bootstrap-$i.sh" 0755 "benign bootstrap snippet" <<EOF
#!/usr/bin/env bash
echo "bootstrap maintenance $i"
EOF
  count=$((count + 1))
done

for i in $(seq 1 20); do
  mkexec monitoring "$ROOT_PREFIX/etc/monitoring/site-check-$i.sh" "benign monitoring helper" <<EOF
#!/usr/bin/env bash
echo "monitoring helper $i"
EOF
  count=$((count + 1))
done

for i in $(seq 1 20); do
  mkexec cert "$ROOT_PREFIX/usr/local/sbin/cert-renew-wrapper-$i" "benign certificate renewal wrapper" <<EOF
#!/usr/bin/env bash
echo "certificate wrapper $i"
EOF
  count=$((count + 1))
done

for i in $(seq 1 20); do
  mkexec network "$ROOT_PREFIX/opt/support/bin/network-helper-$i" "benign network helper script" <<EOF
#!/usr/bin/env bash
echo "network helper $i"
EOF
  count=$((count + 1))
done

if [[ "$count" -ne 1000 ]]; then
  echo "Artifact count mismatch: expected 1000, got $count" >&2
  exit 1
fi

awk -F '\t' 'NR>1{c[$1]++} END{for(k in c) print k "\t" c[k]}' "$MANIFEST" | sort > "$SUMMARY"

echo "Created $count benign administrator artifacts at $ROOT_PREFIX"
echo "Manifest: $MANIFEST"
echo "Summary: $SUMMARY"
