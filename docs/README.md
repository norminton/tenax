# Tenax Analyst Playbook

## Overview

This playbook exists because I ran into a problem.

During an investigation on a compromised Linux server, I realized very quickly that I didn’t fully understand the depth of persistence on Linux.

There was no single place to look.  
No checklist that felt complete.  
No point where I could confidently say, “I’ve covered everything.”

Every time I thought I was done, there was another file path, another mechanism, another place persistence could be hiding.

That’s the reality of Linux.

Persistence isn’t centralized. It’s everywhere.

---

## Why This Exists

This project started as a way to solve that problem for myself.

I wanted:

- a way to **automate the obvious checks**  
- a structured way to **prioritize what matters first**  
- a **complete playbook** I could follow during an investigation  
- a single place to keep **all persistence knowledge and notes**  

Because the truth is:

> **You cannot fully automate Linux persistence analysis.**

There are too many edge cases, too many mechanisms, and too many ways attackers can chain them together.

So instead of trying to automate everything, I built:

- a tool to **surface the most important findings**  
- a playbook to **walk through the rest correctly**  
- a collector to **automate the file system analysis**

And I’m putting it public so nobody else has to figure this out from scratch.

---

## What This Is

This directory is a **complete Linux persistence analysis playbook**.

It is designed to be used **during a real investigation**, not just read once and forgotten.

It gives you:

- a structured workflow  
- deep technical breakdowns of each persistence mechanism  
- guidance on what actually matters vs noise  
- real-world tradecraft context  

---

## Where to Start

If you’re actively investigating a system, start here:

### Analyst Guide
- [Analyst Guide](analyst-guide.md)

This is the playbook.

It walks you through:
- how to approach a Linux investigation  
- how to use Tenax output effectively  
- how to validate persistence  
- how to avoid missing hidden mechanisms  

---

### Module Notes
Located in: [`modules/`](modules/)

This is where the depth is.

Each module breaks down a persistence mechanism:

- how it works  
- how attackers use it  
- what it looks like in real environments  
- how to investigate it properly  

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

> **This is the reference you use when you’re deep in an investigation and need to understand exactly what you’re looking at.**

---

## Supporting Documents

These help you make better decisions while investigating:

- [Triage Principles](triage-principles.md)  
- [False Positives](false-positives.md)  
- [APT Tradecraft Notes](apt-tradecraft-notes.md)  

They provide:
- prioritization guidance  
- validation strategies  
- real-world attacker behavior  

---

## How to Use This

1. Run Tenax and review the **analyze output**  
2. Use the **Analyst Guide** to structure your investigation  
3. Dive into **Module Notes** based on findings  
4. Use supporting docs to refine decisions  

---

## Final Thought

This exists because Linux persistence is deeper than it looks.

If you’ve ever felt like:

- you might be missing something  
- there’s always one more place to check  
- you’re not fully confident the system is clean  

You’re not wrong.

> **The goal isn’t just to find persistence.  
It’s to understand how the attacker is staying on the system.**

That’s what this playbook is built for.
