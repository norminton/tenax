# Tenax Analyst Playbook

## Overview

This directory contains a **complete analyst guide and playbook for identifying Linux persistence**.

The goal of this documentation is to provide a structured, repeatable methodology for:

- identifying persistence mechanisms  
- prioritizing investigation  
- validating suspicious artifacts  
- understanding attacker tradecraft  

This is not just reference material. It is designed to be used **during real investigations**.

---

## Highest Value Documents

If you are actively investigating a system, start here:

### 1. Analyst Guide
- [Analyst Guide](analyst-guide.md)

The **core playbook** for Linux persistence analysis.

Provides:
- step-by-step investigation workflow  
- how to validate findings  
- how to confirm persistence  
- how to avoid common mistakes  

---

### 2. Module Notes
Located in: [`modules/`](modules/)

These are the **most important technical references**.

Each module contains:
- deep explanation of the persistence mechanism  
- real attacker tradecraft  
- detection guidance  
- investigative methodology  

Modules:

- [Cron](modules/cron.md)  
- [Systemd](modules/systemd.md)  
- [Shell Profiles](modules/shell-profiles.md)  
- [SSH](modules/ssh.md)  
- [Sudoers](modules/sudoers.md)  
- [RC / Init](modules/rc-init.md)  
- [Temporary Paths](modules/tmp-paths.md)  
- [LD_PRELOAD](modules/ld-preload.md)  
- [Autostart Hooks](modules/autostart-hooks.md)  
- [At Jobs](modules/at-jobs.md)  
- [Network Hooks](modules/network-hooks.md)  
- [Containers](modules/containers.md)  
- [Environment Hooks](modules/environment-hooks.md)  
- [PAM](modules/pam.md)  
- [Capabilities](modules/capabilities.md)  

> **If you understand the module notes, you understand Linux persistence.**

---

## Supporting Documents

These documents enhance analysis and improve decision-making, but are secondary to the Analyst Guide and Module Notes.

### Investigation Principles

- [Triage Principles](triage-principles.md)  
- [False Positives](false-positives.md)  

Provide:
- prioritization strategy  
- false positive reduction  
- investigation mindset  

---

### Threat Tradecraft

- [APT Tradecraft Notes](apt-tradecraft-notes.md)  

Provides:
- real-world persistence usage by threat actors  
- mapping between techniques and attacker behavior  
- context for why persistence mechanisms are used  

---

## How to Use This Playbook

1. Start with the **Analyst Guide**  
2. Use **Tenax analyze output** to prioritize  
3. Dive into relevant **Module Notes**  
4. Use **Triage Principles** to guide investigation order  
5. Use **False Positives** to validate findings  
6. Use **APT Tradecraft Notes** for context and pattern recognition  

---

## Key Takeaway

This playbook is designed to answer one question:

> **How does an attacker stay on this Linux system?**

If you follow this documentation, you will be able to:

- identify persistence mechanisms  
- understand how they work  
- determine if they are malicious  
- uncover additional hidden persistence  

---

## Final Note

Persistence is rarely a single artifact.

If you find one mechanism, assume there are more.

> **The goal is not to find a file. The goal is to understand the persistence strategy.**
