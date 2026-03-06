# Linux-Persistence-Parser

Goal:
Create an automated bash script that is placed onto a linux host, in which it pulls every known way for file persistence and places all findings within a directory.


```
/etc/crontab
/etc/cron.d/
/etc/cron.hourly/
/etc/cron.daily/
/etc/cron.weekly/
/etc/cron.monthly/
/var/spool/cron/
/var/spool/cron/crontabs/
/etc/systemd/system/
/usr/lib/systemd/system/
/lib/systemd/system/
/etc/init.d/
/etc/rc.local
/etc/profile
/etc/profile.d/
/etc/bash.bashrc
/etc/environment
~/.bashrc
~/.bash_profile
~/.profile
~/.zshrc
~/.ssh/authorized_keys
/root/.ssh/authorized_keys
/etc/ssh/sshd_config
/etc/sudoers
/etc/sudoers.d/
/etc/passwd
/etc/shadow
/etc/ld.so.preload
/etc/ld.so.conf
/etc/ld.so.conf.d/
/etc/modules
/etc/modules-load.d/
/etc/modprobe.d/
/etc/network/if-up.d/
/etc/network/if-down.d/
/etc/network/if-pre-up.d/
/etc/network/if-post-down.d/
/etc/rc0.d/
/etc/rc1.d/
/etc/rc2.d/
/etc/rc3.d/
/etc/rc4.d/
/etc/rc5.d/
/etc/rc6.d/
/usr/local/bin/
/usr/local/sbin/
/opt/
/var/tmp/
/tmp/
/dev/shm/
/var/spool/at/
/var/spool/anacron/
/etc/logrotate.d/
/boot/
/var/lib/systemd/
/home/*/.config/autostart/
```
```
/etc/crontab — System-wide scheduled cron jobs
/etc/cron.d/ — Additional cron job definitions
/etc/cron.hourly/ — Hourly scheduled scripts
/etc/cron.daily/ — Daily scheduled scripts
/etc/cron.weekly/ — Weekly scheduled scripts
/etc/cron.monthly/ — Monthly scheduled scripts
/var/spool/cron/ — User-specific cron job storage
/var/spool/cron/crontabs/ — Per-user cron job files
/etc/systemd/system/ — Custom systemd service definitions
/usr/lib/systemd/system/ — Default systemd service files
/lib/systemd/system/ — System service unit files
/etc/init.d/ — Legacy service initialization scripts
/etc/rc.local — Commands executed during system boot
/etc/profile — System-wide login shell configuration
/etc/profile.d/ — Additional login shell scripts
/etc/bash.bashrc — System-wide interactive bash settings
/etc/environment — Global environment variable definitions
~/.bashrc — User interactive shell configuration
~/.bash_profile — User login shell configuration
~/.profile — User login environment settings
~/.zshrc — User zsh shell configuration
~/.ssh/authorized_keys — Authorized SSH login keys
/root/.ssh/authorized_keys — Root SSH authorized keys
/etc/ssh/sshd_config — SSH server configuration settings
/etc/sudoers — Defines sudo privilege rules
/etc/sudoers.d/ — Additional sudo privilege files
/etc/passwd — Local user account definitions
/etc/shadow — Password hash storage
/etc/ld.so.preload — Force loaded shared libraries
/etc/ld.so.conf — Shared library path configuration
/etc/ld.so.conf.d/ — Additional library path configs
/etc/modules — Kernel modules loaded at boot
/etc/modules-load.d/ — Additional module load configs
/etc/modprobe.d/ — Kernel module configuration files
/etc/network/if-up.d/ — Scripts run after interface up
/etc/network/if-down.d/ — Scripts run after interface down
/etc/network/if-pre-up.d/ — Scripts before interface startup
/etc/network/if-post-down.d/ — Scripts after interface shutdown
/etc/rc0.d/ — Runlevel 0 shutdown scripts
/etc/rc1.d/ — Runlevel 1 single-user scripts
/etc/rc2.d/ — Runlevel 2 multi-user scripts
/etc/rc3.d/ — Runlevel 3 multi-user scripts
/etc/rc4.d/ — Runlevel 4 multi-user scripts
/etc/rc5.d/ — Runlevel 5 graphical startup scripts
/etc/rc6.d/ — Runlevel 6 reboot scripts
/usr/local/bin/ — User-installed executable programs
/usr/local/sbin/ — User-installed administrative executables
/opt/ — Optional application installation directory
/var/tmp/ — Temporary files preserved across reboot
/tmp/ — Temporary world-writable file directory
/dev/shm/ — In-memory shared temporary filesystem
/var/spool/at/ — Scheduled at-job task storage
/var/spool/anacron/ — Anacron scheduled task state
/etc/logrotate.d/ — Log rotation configuration scripts
/boot/ — Bootloader and kernel files
/var/lib/systemd/ — Systemd runtime and service state
/home/*/.config/autostart/ — User graphical autostart programs
```















