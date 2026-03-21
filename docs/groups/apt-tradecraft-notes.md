# APT Tradecraft Notes

## Overview

An Advanced Persistent Threat (APT) is a highly capable, typically state-backed or state-aligned intrusion actor that conducts sustained operations against strategic targets. The defining characteristic is persistence of mission. These actors maintain access, adapt techniques, and are specifically designed to survive remediation efforts.

In Linux environments, persistence tradecraft is rarely isolated. Once an attacker gains meaningful access, especially root-level access, they often deploy multiple mechanisms to ensure continued access, execution, and recovery.

Understanding how APTs persist on Linux systems is critical because it allows analysts to move beyond isolated findings and begin identifying patterns of behavior.

> **Persistence mechanisms are not random. They are deliberate, repeatable, and often reused across operations.**

---

## APT38 / BeagleBoyz

### Background

APT38, associated with North Korean financial operations, has conducted large-scale intrusions into banking infrastructure. Their operations prioritize reliability and repeatable execution, often favoring simple persistence mechanisms that are easy to deploy across multiple systems.

### Persistence Method
- Cron

### Observed Tradecraft

Public reporting confirms the use of cron jobs to maintain execution on compromised Linux systems during FASTCash-related activity.

### Module Reference
- [Cron Persistence](../modules/cron.md)

---

## APT5

### Background

APT5 is a Chinese state-sponsored group known for targeting telecommunications and network infrastructure. Their Linux activity has been strongly associated with exploitation of Citrix ADC systems and other appliance-based environments.

### Persistence Method
- Cron (appliance-based)

### Observed Tradecraft

APT5 has been observed modifying crontab files and placing artifacts within `/var/cron/tabs/`, along with associated payloads in temporary directories.

### Module Reference
- [Cron Persistence](../modules/cron.md)

---

## APT29

### Background

APT29, also known as Cozy Bear, is a Russian state-sponsored espionage group known for long-term, stealth-focused intrusions. Their operations prioritize persistence that survives reboots and blends into legitimate system behavior.

### Persistence Method
- RC / init scripts

### Observed Tradecraft

APT29 has been observed installing run commands that execute malware at system startup through RC-style initialization mechanisms.

### Module Reference
- [RC / Init Persistence](../modules/rc-init.md)

---

## Sandworm (Ukraine Power Attack)

### Background

Sandworm is a Russian military cyber unit known for destructive operations against critical infrastructure, including attacks on Ukrainian energy systems.

### Persistence Method
- Systemd services

### Observed Tradecraft

During the 2022 Ukraine Electric Power attack, Sandworm configured systemd services using `WantedBy=multi-user.target` to ensure execution during system startup.

### Module Reference
- [Systemd Persistence](../modules/systemd.md)

---

## APT41

### Background

APT41 is a Chinese threat group that blends espionage and financially motivated activity. Their Linux tradecraft includes stealth-focused persistence mechanisms that avoid obvious execution triggers.

### Persistence Method
- LD_PRELOAD

### Observed Tradecraft

APT41 has been observed configuring payloads to load via the `LD_PRELOAD` environment variable, forcing malicious shared objects to be injected into process execution.

### Module Reference
- [LD_PRELOAD Persistence](../modules/ld-preload.md)

---

## Aquatic Panda

### Background

Aquatic Panda is a China-linked threat group associated with targeting telecommunications providers and large enterprises, frequently deploying Winnti-based tooling.

### Persistence Method
- `/etc/ld.so.preload`

### Observed Tradecraft

Aquatic Panda has been observed modifying system-wide preload configuration to ensure malicious shared libraries are loaded into processes.

### Module Reference
- [LD_PRELOAD Persistence](../modules/ld-preload.md)

---

## Earth Lusca

### Background

Earth Lusca is a threat group known for targeting Linux servers and web infrastructure, often focusing on maintaining long-term access rather than overt execution persistence.

### Persistence Method
- SSH authorized keys

### Observed Tradecraft

Earth Lusca has been observed placing attacker-controlled SSH keys into `/root/.ssh/authorized_keys` to maintain persistent access.

### Module Reference
- [SSH Persistence](../modules/ssh.md)

---

## Salt Typhoon

### Background

Salt Typhoon has been linked to large-scale intrusions into telecommunications infrastructure, often operating on embedded or appliance-based Linux systems.

### Persistence Method
- SSH authorized keys

### Observed Tradecraft

Salt Typhoon has been observed adding SSH keys under root or administrative users on Linux-based network devices.

### Module Reference
- [SSH Persistence](../modules/ssh.md)

---

## TeamTNT

### Background

TeamTNT is a financially motivated threat group known for targeting cloud environments, particularly exposed Docker and Kubernetes infrastructure.

### Persistence Method
- SSH keys  
- Systemd services  

### Observed Tradecraft

TeamTNT has been observed inserting SSH keys into `authorized_keys` files and creating systemd services to maintain execution of cryptomining workloads.

### Module References
- [SSH Persistence](../modules/ssh.md)  
- [Systemd Persistence](../modules/systemd.md)

---

## UNC3886

### Background

UNC3886 is a highly stealthy threat cluster known for targeting network infrastructure and virtualization platforms, often using low-noise persistence techniques.

### Persistence Method
- RC/init scripts

### Observed Tradecraft

UNC3886 has been observed placing scripts within `/etc/rc.local.d/` to execute during system startup.

### Module Reference
- [RC / Init Persistence](../modules/rc-init.md)

---

## Velvet Ant

### Background

Velvet Ant has been observed targeting F5 BIG-IP devices, modifying system startup behavior to maintain persistence on specialized Linux-based appliances.

### Persistence Method
- RC/local

### Observed Tradecraft

Velvet Ant has been observed modifying `/etc/rc.local` to execute attacker-controlled scripts at boot.

### Module Reference
- [RC / Init Persistence](../modules/rc-init.md)

---

## Scattered Spider

### Background

Scattered Spider is a financially motivated threat group known for leveraging legitimate tools and infrastructure to maintain persistence and evade detection.

### Persistence Method
- Systemd with legitimate tooling

### Observed Tradecraft

Scattered Spider has been observed deploying remote access tooling such as Teleport and maintaining persistence through systemd service configuration.

### Module Reference
- [Systemd Persistence](../modules/systemd.md)

---

## Contagious Interview

### Background

Contagious Interview is a campaign targeting developers and job seekers, delivering malware through social engineering and development workflows.

### Persistence Method
- XDG autostart

### Observed Tradecraft

This campaign has been observed creating `.desktop` autostart entries to execute malware during user login sessions.

### Module Reference
- [Autostart Persistence](../modules/autostart-hooks.md)

---

## Rocke

### Background

Rocke is a cryptomining-focused threat group that has extensively targeted Linux servers and cloud environments, often combining stealth and execution persistence techniques.

### Persistence Method
- LD_PRELOAD  
- Systemd  

### Observed Tradecraft

Rocke has been observed modifying `/etc/ld.so.preload` to hide mining activity and using systemd services to maintain execution.

### Module References
- [LD_PRELOAD Persistence](../modules/ld-preload.md)  
- [Systemd Persistence](../modules/systemd.md)

---

## Key Takeaways

### Persistence is Layered

APT actors commonly combine:

- access persistence  
- execution persistence  
- stealth persistence  

---

### Root Access Enables Full Persistence

Once root access is achieved, attackers can:

- modify authentication mechanisms  
- control system startup  
- hijack execution  
- deploy recovery mechanisms  

---

### Tradecraft is Consistent

Across public reporting, the same persistence mechanisms appear repeatedly:

- cron  
- systemd  
- SSH keys  
- RC/init  
- loader hijacking  

> **Understanding these patterns allows analysts to anticipate attacker behavior instead of reacting to individual artifacts.**
