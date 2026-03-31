#!/usr/bin/env bash
set -euo pipefail

LAB_BASE="${LAB_BASE:-/opt/tenax-benign15000}"
ROOT_PREFIX="${ROOT_PREFIX:-$LAB_BASE/rootfs}"
LOG_DIR="$LAB_BASE/log"
MANIFEST="$LAB_BASE/manifest.tsv"
SUMMARY="$LOG_DIR/summary.txt"
MARKER="$LAB_BASE/CREATED_BY_TENAX_BENIGN_15000"
TEARDOWN="$LAB_BASE/teardown.sh"
TARGET_ARTIFACTS=15000

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
printf 'LAB_BASE=%s\nROOT_PREFIX=%s\nTARGET_ARTIFACTS=%s\n' "$LAB_BASE" "$ROOT_PREFIX" "$TARGET_ARTIFACTS" > "$MARKER"

count=0

record() {
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$MANIFEST"
  count=$((count + 1))
}

mkfile() {
  local category="$1" path="$2" mode="$3" note="$4"
  mkdir -p "$(dirname "$path")"
  cat > "$path"
  chmod "$mode" "$path"
  record "$category" "$path" "$note"
}

mktext() {
  local category="$1" path="$2" mode="$3" note="$4" content="$5"
  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$content" > "$path"
  chmod "$mode" "$path"
  record "$category" "$path" "$note"
}

mkexec() {
  mkfile "$1" "$2" 0755 "$3"
}

pick() {
  local array_name="$1" index="$2"
  declare -n array_ref="$array_name"
  printf '%s' "${array_ref[$((index % ${#array_ref[@]}))]}"
}

slug() {
  local value="${1,,}"
  value="${value// /-}"
  value="${value//_/-}"
  value="${value//\//-}"
  printf '%s' "$value"
}

PERSONAS=(
  ubuntu analyst opsadmin appsvc dbadmin devops helpdesk backupsvc secops qa release
  support engineer sre buildsvc webops finops hrapps analytics intern salesops auditops
  noc printsvc apiuser deploysvc
)
TEAMS=(platform support infra sre release qa helpdesk analytics finance identity desktop network web database compliance)
AREAS=(backup cache config logs packages metrics sessions journals archives certificates inventory support tmp mounts locale updates printers)
TASKS=(collect rotate sync report refresh prune verify index reconcile stage audit repair clean validate snapshot inspect publish summarize maintain)
SYSTEM_UNITS=(ssh cron rsyslog apache2 nginx postgresql mysql redis docker containerd systemd-journald unattended-upgrades)
USER_TOOLS=(terminal-notifier keyring-refresh locale-bootstrap desktop-session shell-alias-loader notes-cache warmup git-credential-helper launcher-favorites)
ENV_NAMES=(SITE_REGION HELP_DESK_QUEUE ASSET_TAG_PREFIX PROXY_DOMAIN PATCH_WINDOW MONITORING_SITE BACKUP_POLICY DESKTOP_THEME SUPPORT_TIER CONFIG_RING)
ENV_VALS=(iad-1 dfw-2 localops corp.example saturday-0200 bronze standard blue silver prod stable monthly weekly)
SUDO_CMDS=(
  "/usr/bin/systemctl status apache2"
  "/usr/bin/systemctl status ssh"
  "/usr/bin/journalctl -u rsyslog"
  "/usr/bin/journalctl -u cron"
  "/usr/bin/dpkg -l"
  "/usr/bin/apt-cache policy"
  "/usr/bin/find /var/log -maxdepth 1 -type f -print"
  "/usr/bin/systemctl list-units --type=service"
  "/usr/bin/ss -plnt"
  "/usr/bin/du -sh /var/log"
)
PROFILE_LINES=(
  "export EDITOR=vim"
  "export PAGER=less"
  "export LESS='-FRX'"
  "export HISTCONTROL=ignoreboth:erasedups"
  "export NO_PROXY=localhost,127.0.0.1,::1,169.254.169.254"
  "umask 022"
  "test -d /usr/local/bin && PATH=/usr/local/bin:\$PATH"
  "test -d \$HOME/.local/bin && PATH=\$HOME/.local/bin:\$PATH"
  "alias ll='ls -alF'"
  "alias gs='git status -sb'"
)
BENIGN_COMMENTS=(
  "local operations helper"
  "packaging compatibility wrapper"
  "site support routine"
  "inventory capture helper"
  "certificate maintenance note"
  "desktop defaults helper"
  "application support wrapper"
  "routine service validation"
  "host hygiene helper"
  "asset inventory support"
)
READ_ONLY_COMMANDS=(
  "date -u"
  "hostnamectl --static 2>/dev/null || hostname"
  "uname -r"
  "systemctl is-system-running 2>/dev/null || true"
  "df -h / /var 2>/dev/null || true"
  "journalctl --no-pager -n 5 2>/dev/null || true"
  "find /var/log -maxdepth 1 -type f | sort | head -n 10"
  "ls -1 /etc/systemd/system 2>/dev/null | head -n 10"
  "getent passwd | cut -d: -f1 | head -n 10"
  "ss -plnt 2>/dev/null | head -n 10 || true"
)
ON_CALENDARS=(
  "daily"
  "weekly"
  "monthly"
  "*-*-* 02:00:00"
  "*-*-* 04:30:00"
  "Mon..Fri *-*-* 06:15:00"
  "Sat *-*-* 03:45:00"
)
BOOTSTRAP_PHASES=(instance-init first-login package-refresh motd-refresh support-cache ca-bundle-check locale-fix timezone-note)
DESKTOP_CATEGORIES=(Utility Settings System Monitor Development Office)
LOG_PATHS=(/var/log/syslog /var/log/auth.log /var/log/kern.log /var/log/nginx/access.log /var/log/apache2/error.log /var/log/postgresql/postgresql-14-main.log)
APP_STACKS=(billing portal api worker search reporting ingest scheduler support wiki ci)

COMMON_DIRS=(
  "$ROOT_PREFIX/usr/lib/systemd/system"
  "$ROOT_PREFIX/etc/systemd/system"
  "$ROOT_PREFIX/etc/systemd/system/ssh.service.d"
  "$ROOT_PREFIX/etc/systemd/system/cron.service.d"
  "$ROOT_PREFIX/etc/systemd/system/nginx.service.d"
  "$ROOT_PREFIX/etc/profile.d"
  "$ROOT_PREFIX/usr/local/bin"
  "$ROOT_PREFIX/usr/local/sbin"
  "$ROOT_PREFIX/usr/local/lib/site-admin"
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
  "$ROOT_PREFIX/etc/xdg/autostart"
  "$ROOT_PREFIX/var/lib/cloud/scripts/per-instance"
  "$ROOT_PREFIX/var/lib/site-admin"
  "$ROOT_PREFIX/var/lib/site-admin/backups"
  "$ROOT_PREFIX/var/lib/site-admin/inventory"
  "$ROOT_PREFIX/var/lib/site-admin/pkg-hooks"
  "$ROOT_PREFIX/etc/monitoring"
  "$ROOT_PREFIX/etc/monitoring/plugins"
  "$ROOT_PREFIX/etc/support"
  "$ROOT_PREFIX/etc/site-admin"
)

for dir_path in "${COMMON_DIRS[@]}"; do
  mkdir -p "$dir_path"
done

for persona in "${PERSONAS[@]}"; do
  mkdir -p \
    "$ROOT_PREFIX/home/$persona/.config/systemd/user" \
    "$ROOT_PREFIX/home/$persona/.config/autostart" \
    "$ROOT_PREFIX/home/$persona/.local/bin" \
    "$ROOT_PREFIX/home/$persona/.cache" \
    "$ROOT_PREFIX/home/$persona/bin"
done

write_standard_helper() {
  local path="$1" purpose="$2" comment="$3" cmd_a="$4" cmd_b="$5"
  mkexec "$6" "$path" "$comment" <<EOF
#!/usr/bin/env bash
set -eu
# $purpose
$cmd_a >/dev/null 2>&1 || true
$cmd_b >/dev/null 2>&1 || true
printf '%s\n' "$purpose"
EOF
}

for i in $(seq 1 1000); do
  team="$(pick TEAMS "$i")"
  area="$(pick AREAS "$((i + 3))")"
  task="$(pick TASKS "$((i + 7))")"
  stack="$(pick APP_STACKS "$((i + 11))")"
  helper="/usr/local/sbin/$(slug "$team")-$(slug "$task")-$(slug "$area")-$i"
  unit_name="$(slug "$team")-$(slug "$task")-$(slug "$area")-$i"
  comment="$(pick BENIGN_COMMENTS "$((i + 5))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$i")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 4))")"
  write_standard_helper "$ROOT_PREFIX$helper" "$team $task for $area on $stack" "$comment" "$cmd_a" "$cmd_b" "systemd-helper"
  mkfile systemd-service "$ROOT_PREFIX/usr/lib/systemd/system/$unit_name.service" 0644 "benign systemd service for $team $area" <<EOF
[Unit]
Description=$team $task $area helper $i
After=network-online.target local-fs.target
Documentation=file://$helper

[Service]
Type=oneshot
User=root
ExecStart=$helper
Nice=5

[Install]
WantedBy=multi-user.target
EOF
done

for i in $(seq 1 900); do
  team="$(pick TEAMS "$((i + 1))")"
  area="$(pick AREAS "$((i + 6))")"
  task="$(pick TASKS "$((i + 9))")"
  unit_name="$(slug "$team")-$(slug "$task")-$(slug "$area")-$i"
  calendar="$(pick ON_CALENDARS "$i")"
  mkfile systemd-timer "$ROOT_PREFIX/usr/lib/systemd/system/$unit_name.timer" 0644 "benign timer for $team $area" <<EOF
[Unit]
Description=$team $task $area timer $i

[Timer]
OnCalendar=$calendar
Persistent=true
RandomizedDelaySec=20m
Unit=$unit_name.service

[Install]
WantedBy=timers.target
EOF
done

for i in $(seq 1 700); do
  base_unit="$(pick SYSTEM_UNITS "$i")"
  team="$(pick TEAMS "$((i + 2))")"
  env_name="$(pick ENV_NAMES "$i")"
  env_val="$(pick ENV_VALS "$((i + 3))")"
  dropin_dir="$ROOT_PREFIX/etc/systemd/system/$base_unit.service.d"
  mkdir -p "$dropin_dir"
  mkfile systemd-dropin "$dropin_dir/20-$(slug "$team")-$i.conf" 0644 "benign systemd drop-in for $base_unit" <<EOF
[Service]
Environment=$env_name=$env_val
EOF
done

for i in $(seq 1 800); do
  persona="$(pick PERSONAS "$i")"
  task="$(pick TASKS "$((i + 2))")"
  area="$(pick AREAS "$((i + 4))")"
  stack="$(pick APP_STACKS "$((i + 6))")"
  mkfile user-service "$ROOT_PREFIX/home/$persona/.config/systemd/user/$(slug "$task")-$(slug "$area")-$i.service" 0644 "benign user systemd service for $persona" <<EOF
[Unit]
Description=$persona $task $area helper $i

[Service]
Type=oneshot
ExecStart=/usr/bin/printf '%s\n' '$persona $task $area for $stack'

[Install]
WantedBy=default.target
EOF
done

for i in $(seq 1 500); do
  persona="$(pick PERSONAS "$((i + 3))")"
  task="$(pick TASKS "$((i + 5))")"
  area="$(pick AREAS "$((i + 7))")"
  calendar="$(pick ON_CALENDARS "$((i + 1))")"
  mkfile user-timer "$ROOT_PREFIX/home/$persona/.config/systemd/user/$(slug "$task")-$(slug "$area")-$i.timer" 0644 "benign user timer for $persona" <<EOF
[Unit]
Description=$persona $task $area timer $i

[Timer]
OnCalendar=$calendar
Persistent=true
RandomizedDelaySec=10m
Unit=$(slug "$task")-$(slug "$area")-$i.service

[Install]
WantedBy=timers.target
EOF
done

for i in $(seq 1 600); do
  team="$(pick TEAMS "$((i + 4))")"
  line="$(pick PROFILE_LINES "$i")"
  mkfile profile.d "$ROOT_PREFIX/etc/profile.d/$(slug "$team")-defaults-$i.sh" 0644 "benign profile defaults for $team" <<EOF
# login defaults for $team
$line
EOF
done

for i in $(seq 1 900); do
  team="$(pick TEAMS "$((i + 2))")"
  area="$(pick AREAS "$((i + 5))")"
  task="$(pick TASKS "$((i + 8))")"
  bin_dir=$([[ $((i % 2)) -eq 0 ]] && printf '/usr/local/bin' || printf '/usr/local/sbin')
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 2))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 7))")"
  write_standard_helper "$ROOT_PREFIX$bin_dir/$(slug "$team")-$(slug "$task")-$(slug "$area")-$i" "$team $task wrapper for $area" "benign local wrapper" "$cmd_a" "$cmd_b" "local-wrapper"
done

for i in $(seq 1 800); do
  base_dir=$(
    if [[ $((i % 3)) -eq 0 ]]; then
      printf '/opt/platform/bin'
    elif [[ $((i % 2)) -eq 0 ]]; then
      printf '/opt/support/bin'
    else
      printf '/opt/ops/bin'
    fi
  )
  team="$(pick TEAMS "$((i + 6))")"
  area="$(pick AREAS "$((i + 1))")"
  task="$(pick TASKS "$((i + 9))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 3))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 8))")"
  write_standard_helper "$ROOT_PREFIX$base_dir/$(slug "$team")-$(slug "$task")-$(slug "$area")-$i" "$team $task helper in /opt for $area" "benign /opt wrapper" "$cmd_a" "$cmd_b" "opt-wrapper"
done

for i in $(seq 1 650); do
  team="$(pick TEAMS "$((i + 4))")"
  area="$(pick AREAS "$((i + 10))")"
  task="$(pick TASKS "$((i + 13))")"
  minute=$((i % 60))
  hour=$(((i / 7) % 24))
  mkfile cron "$ROOT_PREFIX/etc/cron.d/$(slug "$team")-$(slug "$task")-$i" 0644 "benign cron.d entry for $team" <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$minute $hour * * * root /usr/local/sbin/$(slug "$team")-$(slug "$task")-$(slug "$area")-$(((i % 900) + 1))
EOF
done

for i in $(seq 1 350); do
  area="$(pick AREAS "$((i + 5))")"
  task="$(pick TASKS "$((i + 11))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$i")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 6))")"
  write_standard_helper "$ROOT_PREFIX/etc/cron.daily/$(slug "$task")-$(slug "$area")-$i" "daily $task for $area" "benign cron.daily helper" "$cmd_a" "$cmd_b" "cron-daily"
done

for i in $(seq 1 200); do
  area="$(pick AREAS "$((i + 7))")"
  task="$(pick TASKS "$((i + 14))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 2))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 5))")"
  write_standard_helper "$ROOT_PREFIX/etc/cron.weekly/$(slug "$task")-$(slug "$area")-$i" "weekly $task for $area" "benign cron.weekly helper" "$cmd_a" "$cmd_b" "cron-weekly"
done

for i in $(seq 1 850); do
  team="$(pick TEAMS "$((i + 3))")"
  area="$(pick AREAS "$((i + 8))")"
  task="$(pick TASKS "$((i + 12))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 1))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 9))")"
  write_standard_helper "$ROOT_PREFIX/var/lib/site-admin/$(slug "$team")-$(slug "$task")-$(slug "$area")-$i.sh" "$team maintenance helper for $area" "benign maintenance script" "$cmd_a" "$cmd_b" "maintenance"
done

for i in $(seq 1 450); do
  team="$(pick TEAMS "$((i + 2))")"
  stack="$(pick APP_STACKS "$((i + 6))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 3))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 7))")"
  write_standard_helper "$ROOT_PREFIX/var/lib/site-admin/backups/$(slug "$stack")-backup-catalog-$i.sh" "$team backup catalog helper for $stack" "benign backup inventory helper" "$cmd_a" "$cmd_b" "backup"
done

for i in $(seq 1 400); do
  team="$(pick TEAMS "$((i + 4))")"
  area="$(pick AREAS "$((i + 9))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 2))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 8))")"
  write_standard_helper "$ROOT_PREFIX/var/lib/site-admin/inventory/$(slug "$team")-$(slug "$area")-inventory-$i.sh" "$team inventory helper for $area" "benign inventory script" "$cmd_a" "$cmd_b" "inventory"
done

for i in $(seq 1 400); do
  team="$(pick TEAMS "$((i + 1))")"
  area="$(pick AREAS "$((i + 3))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 4))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 9))")"
  write_standard_helper "$ROOT_PREFIX/etc/monitoring/plugins/$(slug "$team")-$(slug "$area")-check-$i.sh" "$team monitoring helper for $area" "benign monitoring wrapper" "$cmd_a" "$cmd_b" "monitoring"
done

for i in $(seq 1 350); do
  unit="$(pick SYSTEM_UNITS "$i")"
  team="$(pick TEAMS "$((i + 5))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 1))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 7))")"
  write_standard_helper "$ROOT_PREFIX/usr/local/lib/site-admin/$(slug "$team")-restart-helper-$i" "$team patch readiness helper for $unit" "benign patch and restart helper" "$cmd_a" "$cmd_b" "patch-helper"
done

for i in $(seq 1 450); do
  log_path="$(pick LOG_PATHS "$i")"
  area="$(pick AREAS "$((i + 4))")"
  rotate_count=$((7 + (i % 10)))
  mkfile logrotate "$ROOT_PREFIX/etc/logrotate.d/$(basename "$log_path" | tr '.' '-')-$i" 0644 "benign logrotate snippet for $area" <<EOF
$log_path {
    rotate $rotate_count
    weekly
    missingok
    notifempty
    compress
    delaycompress
}
EOF
done

for i in $(seq 1 450); do
  env_name="$(pick ENV_NAMES "$i")"
  env_val="$(pick ENV_VALS "$((i + 6))")"
  team="$(pick TEAMS "$((i + 2))")"
  mkfile environment "$ROOT_PREFIX/etc/default/$(slug "$team")-$i" 0644 "benign environment file for $team" <<EOF
$env_name=$env_val
EOF
done

for i in $(seq 1 350); do
  area="$(pick AREAS "$((i + 5))")"
  owner=$([[ $((i % 5)) -eq 0 ]] && printf 'www-data' || printf 'root')
  mkfile tmpfiles "$ROOT_PREFIX/etc/tmpfiles.d/$(slug "$area")-cache-$i.conf" 0644 "benign tmpfiles snippet for $area" <<EOF
d /var/cache/$(slug "$area")-$i 0755 $owner root -
EOF
done

for i in $(seq 1 300); do
  persona="$(pick PERSONAS "$i")"
  cmd="$(pick SUDO_CMDS "$((i + 4))")"
  mkfile sudoers "$ROOT_PREFIX/etc/sudoers.d/$(slug "$persona")-$i" 0440 "benign sudoers include for $persona" <<EOF
$persona ALL=(root) NOPASSWD: $cmd
EOF
done

for i in $(seq 1 250); do
  if [[ $((i % 2)) -eq 0 ]]; then
    team="$(pick TEAMS "$((i + 1))")"
    mkfile pam "$ROOT_PREFIX/etc/pam.d/$(slug "$team")-motd-$i" 0644 "benign PAM reference for $team" <<EOF
# local note for $team
session optional pam_motd.so motd=/run/motd.dynamic
EOF
  else
    team="$(pick TEAMS "$((i + 3))")"
    mkfile security "$ROOT_PREFIX/etc/security/$(slug "$team")-access-$i.conf" 0644 "benign access policy note for $team" <<EOF
# support console note for $team
# approved interactive maintenance windows may use local console access
EOF
  fi
done

for i in $(seq 1 250); do
  phase="$(pick BOOTSTRAP_PHASES "$i")"
  team="$(pick TEAMS "$((i + 4))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 3))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 8))")"
  write_standard_helper "$ROOT_PREFIX/var/lib/cloud/scripts/per-instance/$(slug "$phase")-$i.sh" "$team bootstrap note for $phase" "benign cloud/bootstrap snippet" "$cmd_a" "$cmd_b" "cloud"
done

for i in $(seq 1 250); do
  stack="$(pick APP_STACKS "$i")"
  team="$(pick TEAMS "$((i + 5))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 1))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 6))")"
  write_standard_helper "$ROOT_PREFIX/usr/local/sbin/$(slug "$stack")-cert-renew-note-$i" "$team certificate helper for $stack" "benign certificate renewal wrapper" "$cmd_a" "$cmd_b" "cert"
done

for i in $(seq 1 450); do
  persona="$(pick PERSONAS "$((i + 2))")"
  tool="$(pick USER_TOOLS "$i")"
  category="$(pick DESKTOP_CATEGORIES "$((i + 4))")"
  mkfile autostart "$ROOT_PREFIX/home/$persona/.config/autostart/$(slug "$tool")-$i.desktop" 0644 "benign user autostart for $persona" <<EOF
[Desktop Entry]
Type=Application
Name=$(printf '%s' "$tool" | tr '-' ' ') $i
Exec=/usr/bin/printf '%s\n' '$persona $tool helper'
X-GNOME-Autostart-enabled=true
Categories=$category;
EOF
done

for i in $(seq 1 200); do
  tool="$(pick USER_TOOLS "$((i + 5))")"
  category="$(pick DESKTOP_CATEGORIES "$i")"
  mkfile xdg-autostart "$ROOT_PREFIX/etc/xdg/autostart/$(slug "$tool")-$i.desktop" 0644 "benign system desktop autostart" <<EOF
[Desktop Entry]
Type=Application
Name=Site $(printf '%s' "$tool" | tr '-' ' ') $i
Exec=/usr/bin/printf '%s\n' 'site desktop helper $tool'
OnlyShowIn=GNOME;XFCE;Unity;
Categories=$category;
EOF
done

for i in $(seq 1 650); do
  persona="$(pick PERSONAS "$((i + 7))")"
  area="$(pick AREAS "$((i + 4))")"
  task="$(pick TASKS "$((i + 10))")"
  home_dir="$ROOT_PREFIX/home/$persona"
  subdir=$([[ $((i % 2)) -eq 0 ]] && printf '.local/bin' || printf 'bin')
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 2))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 5))")"
  write_standard_helper "$home_dir/$subdir/$(slug "$task")-$(slug "$area")-$i" "$persona helper for $task $area" "benign user helper script" "$cmd_a" "$cmd_b" "home-script"
done

for i in $(seq 1 250); do
  stack="$(pick APP_STACKS "$((i + 1))")"
  unit="$(pick SYSTEM_UNITS "$((i + 3))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 2))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 6))")"
  write_standard_helper "$ROOT_PREFIX/etc/monitoring/$(slug "$stack")-$(slug "$unit")-health-$i.sh" "$stack health check for $unit" "benign service health check" "$cmd_a" "$cmd_b" "health-check"
done

for i in $(seq 1 200); do
  persona="$(pick PERSONAS "$((i + 4))")"
  team="$(pick TEAMS "$((i + 9))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 1))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 8))")"
  write_standard_helper "$ROOT_PREFIX/usr/local/lib/site-admin/$(slug "$team")-ssh-key-audit-$i" "$persona ssh key audit note for $team" "benign ssh key maintenance helper" "$cmd_a" "$cmd_b" "ssh-maintenance"
done

for i in $(seq 1 100); do
  stack="$(pick APP_STACKS "$((i + 2))")"
  team="$(pick TEAMS "$((i + 5))")"
  cmd_a="$(pick READ_ONLY_COMMANDS "$((i + 2))")"
  cmd_b="$(pick READ_ONLY_COMMANDS "$((i + 9))")"
  write_standard_helper "$ROOT_PREFIX/var/lib/site-admin/pkg-hooks/$(slug "$stack")-postinst-note-$i.sh" "$team package-maintainer helper for $stack" "benign package maintenance style helper" "$cmd_a" "$cmd_b" "package-helper"
done

cat > "$TEARDOWN" <<EOF
#!/usr/bin/env bash
set -euo pipefail

LAB_BASE="${LAB_BASE:-$LAB_BASE}"
MARKER="$MARKER"

if [[ ! -f "\$MARKER" ]]; then
  echo "Refusing teardown: marker not found at \$MARKER" >&2
  exit 1
fi

case "\$LAB_BASE" in
  /opt/tenax-benign*) rm -rf -- "\$LAB_BASE" ;;
  *) echo "Refusing teardown for unexpected LAB_BASE: \$LAB_BASE" >&2; exit 1 ;;
esac

echo "Removed \$LAB_BASE"
EOF
chmod 0755 "$TEARDOWN"

if [[ "$count" -ne "$TARGET_ARTIFACTS" ]]; then
  echo "Artifact count mismatch: expected $TARGET_ARTIFACTS, got $count" >&2
  exit 1
fi

{
  printf 'artifact_count\t%s\n' "$count"
  awk -F '\t' 'NR>1{c[$1]++} END{for(k in c) print k "\t" c[k]}' "$MANIFEST" | sort
  printf 'teardown\t%s\n' "$TEARDOWN"
} > "$SUMMARY"

echo "Created $count benign administrator artifacts at $ROOT_PREFIX"
echo "Manifest: $MANIFEST"
echo "Summary: $SUMMARY"
echo "Teardown: $TEARDOWN"
