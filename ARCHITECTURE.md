# VARIANT — Architecture

> This is the **living technical reference**. If the code disagrees  
> with this document, the code is wrong.
>
> Strategic vision → `vision.md` §11.  
> Engineering execution policy → `GEMINI.md`.  
> This document → every architectural decision the engine follows.

---

## §0 Purpose

VARIANT is a composable security-world simulator. It generates
full-spectrum offensive and defensive scenarios from declarative
configurations. Every VM, every network, every service, every
attack, every defense runs inside one browser tab.

The purpose is threefold:

1. **Train practitioners** who can think about systems — not just
   follow playbooks. From a teenager's first XSS to a SOC analyst
   surviving an APT campaign.

2. **Feed the flywheel.** Players who graduate to defense write
   INVARIANT rules tested against real attack data. Rules reach
   production. Players become hirable. Employers deploy sensors.
   Sensors feed data back into the game.

3. **Build the engine** anyone can use to create levels — Roblox
   for cybersecurity. Full configurability. Full extensibility.
   No gatekeeping.

---

## §1 Foundational Constraints

These are load-bearing walls. Every system in the engine follows
from these. Violating any of them is a bug.

### §1.1 Everything Is In The Browser

Every VM, every network frame, every DNS query, every email, every
fake cloud console runs in the player's browser tab. Zero server
compute during gameplay.

**Why:** Destructive freedom. If anything runs on our servers a
player can crash it for everyone. In the browser, they can deploy
ransomware, wipe disks, nuke services — close the tab, gone.

**What lives on our servers:**
- CDN (R2/Pages): WASM binary, disk images, WorldSpec JSON, assets. **Read-only.**
- INVARIANT Bridge API: payload fetches, rule submission. **Optional.**
- Score/profile API: leaderboard, portfolio. **Optional.**

**What lives in the browser tab:**
- Backend instances (v86, Simulacra, any registered backend)
- Network fabric (JavaScript Ethernet switch)
- DNS resolver (air-gapped, VARIANT domains only)
- VARIANT Internet (simulated external services)
- Lens UI (React)
- Event bus, objective tracker, scoring engine
- All registries

### §1.2 The Chromebook Constraint

The floor device is a **school Chromebook with 4GB RAM.** ChromeOS
uses ~1.5GB. Chrome ~500MB. We get ~1-1.5GB.

| Tier | RAM Budget | Who |
|---|---|---|
| Beginner | < 100MB | School students. Pure Simulacra. Instant load. |
| Intermediate | < 300MB | Learning lateral movement. 1 v86 + Simulacra. |
| Advanced | < 600MB | Enterprise scenarios. 1 v86 + Simulacrum+. |
| Expert | < 1GB | SOC workstation. Multiple VMs. |
| Extreme | 1-2GB+ | APT campaign. Expert hardware expected. |

The **level designer decides.** The engine estimates resources and
warns the player before loading. The `ResourceEstimator` categorizes
every WorldSpec into a tier.

### §1.3 Real Linux. Not Simulated.

The terminal is not simulated. v86 boots **real Alpine Linux** in
WebAssembly. Real bash. Real grep. Real nmap. Real curl. Real Python.
Player skills transfer directly to production environments.

### §1.4 Air-Gapped By Construction

Triple isolation — no configuration, no flag, no workaround breaks this:

1. **Guest OS:** `iptables DROP` all OUTPUT to non-VARIANT IPs
2. **Network Fabric:** JavaScript switch drops frames to non-VARIANT destinations
3. **v86 NIC:** NE2K connects only to BroadcastChannel — no physical network path

### §1.5 Total Destructive Freedom

Everything is in the browser. The world is air-gapped. There is nothing
real to protect. We actively reward destruction.

### §1.6 Responsible Escape

If someone escapes the sandbox: they are rewarded, we take responsibility,
we fix and credit them publicly.

**Bright lines:** (1) Never touch non-Santh infra. (2) Never access other
users' data. (3) No sustained destruction after discovery.

### §1.7 WorldSpec Is Pure Data

Every level is a JSON document. It composes primitives. It cannot
execute arbitrary code.

**Rule:** If a level author needs to write a function, the WorldSpec
is missing a primitive. We add the primitive. We never add callbacks.

### §1.8 Terminal First

Every level starts in a terminal. Full-screen xterm.js connected to
real Linux. Blinking cursor. No menus. Players type commands into a
real shell.

Additional lenses open from the terminal via custom commands that
emit OSC escape sequences over the serial line. The UI intercepts
them and opens the corresponding panel.

### §1.9 Everything Is A Registry

Every extensible subsystem follows the same pattern:

1. Define a contract (TypeScript interface)
2. Create a registry (append-only `Map<string, Definition>`)
3. Register implementations at engine initialization
4. Discover at runtime by querying the registry

**All registries share these security properties:**
- **Append-only** — no overwrites, no deletions
- **Frozen** — mutations on retrieved objects have no effect
- **Namespaced** — third-party keys use `'vendor/feature'` convention

### §1.10 How We Treat Players

1. **We don't gatekeep.** The beginner who doesn't know what a terminal
   is and the expert who wants to simulate a 100-machine APT campaign
   use the same engine. The level designer configures difficulty.

2. **We never lie about mechanics.** Query engines evaluate input
   against data honestly. There is no "right answer" baked in. If a
   creative exploit works, it works. We reward it.

3. **We reward destruction.** Most creative multi-stage chain? Bonus
   points. Crash the server unexpectedly? Achievement unlocked.

4. **We don't look like education.** The gamification is the wrapper.
   The education is the payload. If it smells like a learning platform,
   we failed.

5. **Under 5 minutes per session.** Works on a Chromebook in a browser.
   No install. No login required to play.

6. **Shareable results.** Every session produces a result the player
   can flex. Score, time, stealth, objectives. Creates "can you beat
   level X?" conversations.

### §1.11 How We Treat Level Designers

1. **Full configurability.** Every aspect of the simulation is
   configurable through WorldSpec. If something isn't configurable,
   that's a missing primitive — we add it.

2. **Level designers create worlds, not UIs.** They write JSON. The
   engine renders it. They never touch React components.

3. **Community levels are not second-class.** They have access to every
   machine image, every codebase, every network primitive, every defense
   mechanic. The only restriction is live production intelligence.

4. **Extensibility without core changes.** Register a new service,
   lens, module, objective evaluator, NPC template, or dynamic action
   handler. Zero core modifications required.

---

## §2 Composable Backends

The engine does not dictate how machines run. Level designers choose
per machine. The `BackendRouter` composes them. The fabric connects
them. The player can't tell the difference.

```
Cheap / Scriptable ◄────────────────────────────────► Realistic / Heavy

Simulacrum    Simulacrum+    container2wasm    v86 (Alpine)   CheerpX
(~1-5MB)      (~5-10MB)      (~30-50MB)        (~32-128MB)   (~50MB+)
Scripted      Protocol       Real Linux        Real Linux    JIT x86
shell         proxies        in WASM           emulated      near-
VFS only      + lwIP TCP     container         full x86      native
```

**Current default:** Player machines use v86. Everything else uses
Simulacrum or Simulacrum+.

Backend contract:

```typescript
interface VMBackend {
    boot(config: VMBootConfig): Promise<VMInstance>
    attach(vm: VMInstance, terminal: TerminalEmitter): void
    sendFrame(vm: VMInstance, frame: Uint8Array): void
    onFrame(vm: VMInstance, cb: (frame: Uint8Array) => void): Unsubscribe
    applyOverlay(vm: VMInstance, overlay: FilesystemOverlay): Promise<void>
    snapshot(vm: VMInstance): Promise<Snapshot>
    restore(vm: VMInstance, snap: Snapshot): Promise<void>
    destroy(vm: VMInstance): void
}
```

Any string can be used as a backend type. Custom backends register
via `BackendRouter`. Decade-proof: when WebAssembly Component Model
lands, register a new backend. Zero engine changes.

---

## §3 The Lens System

The simulation is the truth. **A lens is just a way to look at and
interact with that truth.** Adding a new lens never changes the
simulation.

| Lens | What the Player Sees |
|---|---|
| Terminal | Full shell (xterm.js) |
| Web Browser | Rendered web page with tools |
| Email Client | Inbox, compose, read mail |
| File Manager | Visual file browser |
| Network Map | Live topology with traffic |
| Packet Capture | Wireshark-style inspector |
| Database Console | SQL prompt with results |
| Defense Dashboard | SOC overview, ISL editor |
| Cloud Console | Fake AWS/GCP/Azure console |
| Code Editor | Source with syntax highlighting |

**Lenses are windowed.** Tile, stack, or float. SOC analysts and
pentesters work with multiple views. We simulate that.

Lens contract:

```typescript
interface LensDefinition {
    readonly type: string
    readonly displayName: string
    readonly description: string
    readonly icon: string
    readonly capabilities: LensCapabilities
    readonly constraints: LensConstraints
    readonly shortcut: string | null
    readonly allowMultiple: boolean
    readonly lifecycle: LensLifecycle
}
```

Registered via `LensRegistry`. Third-party lenses register themselves.

---

## §4 Network Fabric

Air-gapped JavaScript Ethernet switch. Manages all inter-VM
communication.

```typescript
interface NetworkFabric {
    init(topology: NetworkTopology): void
    connect(vmId: string, segment: string, mac: string): NICHandle
    resolve(query: string): DNSResponse
    registerExternal(domain: string, handler: ExternalHandler): void
    tap(edge: string, cb: (frame: Frame, dir: Direction) => void): Unsubscribe
    destroy(): void
}
```

Features implemented:
- Segment-based routing
- MAC address resolution
- Firewall rules per machine (INPUT/OUTPUT/FORWARD)
- DNS resolution (VARIANT domains only)
- Edge-level traffic tapping
- NAT traversal simulation
- VLAN support

---

## §5 The 10 Registries

| # | Registry | Registers | Who Uses It |
|---|---|---|---|
| 1 | **LensRegistry** | Lens type definitions | Compositor — renders panels |
| 2 | **StartConfigPresetRegistry** | Named start configs | WorldSpec — boot layout |
| 3 | **ServiceHandlerFactory** | Service constructors | Simulacrum — instantiates services |
| 4 | **ProtocolHandlerRegistry** | TCP-level protocol handlers | Simulacrum+ — routes connections |
| 5 | **ModuleRegistry** | Engine modules | Engine — lifecycle management |
| 6 | **DynamicActionHandlerRegistry** | Custom dynamic actions | Dynamics engine — extensible events |
| 7 | **ObjectiveEvaluatorRegistry** | Custom objective evaluators | Objective detector — pluggable win conditions |
| 8 | **NPCTemplateRegistry** | NPC behavior templates | Level designers — pre-built NPCs |
| 9 | **BackendRouter** | VM backend implementations | Engine — machine instantiation |
| 10 | **ResourceEstimator** | Tier classification | Engine — Chromebook constraint enforcement |

Third-party extension pattern:
```typescript
// 1. Define your implementation
const myService: ServiceHandlerConstructor = (config) => createMyService(config);

// 2. Register it (append-only, namespaced)
factory.register('vendor/my-service', myService, { description: '...' });

// 3. Level designers reference it in WorldSpec
{ name: 'vendor/my-service', ports: [8080], autostart: true }
```

---

## §6 WorldSpec — The Universal Level Format

Pure data. No code. Version `2.0`.

```typescript
interface WorldSpec {
    version: '2.0'
    trust: 'community' | 'curated'
    meta: WorldMeta
    machines: Record<string, MachineSpec>
    startMachine: string
    startConfig?: StartConfigSpec
    network: NetworkSpec
    credentials: CredentialEntry[]
    objectives: ObjectiveSpec[]
    gameOver?: GameOverSpec
    dynamics?: DynamicsSpec
    mail?: MailSystemSpec
    variantInternet?: VariantInternetSpec
    modules: string[]
    scoring: ScoringConfig
    hints: string[]
    resources?: ResourceEstimation
    extensions?: Record<string, unknown>
}
```

Every major type has an `extensions` field. Convention:
`'vendor/feature'` keys. The engine passes them through untouched.

---

## §7 The 9-Layer Primitive Taxonomy

Everything in VARIANT is composed from these primitives. A level
author writes JSON. The engine interprets it.

| Layer | Name | What It Contains |
|---|---|---|
| 0 | **Physical** | Devices, hardware capabilities, USB, NFC, serial |
| 1 | **Network** | Segments, edges, firewall rules, DNS zones |
| 2 | **Machine** | Real Linux or Simulacrum. Users, VFS, services, processes |
| 3 | **Identity** | Credentials as attack graph edges. Password, key, token, cert, ticket |
| 4 | **Services** | HTTP, SSH, SMTP, DNS, MySQL, Redis, SMB, FTP, Cloud Metadata, C2 |
| 5 | **Vulnerability** | Query engines shared with INVARIANT: SQL, Shell, Template, XML, LDAP, JWT, Path, SSRF, Deserialize |
| 6 | **Defense** | WAF, rate limiting, IDS, honeypot, security headers, CORS, INVARIANT rules |
| 7 | **Actor** | Player-earned capabilities: shell, creds, persistence, botnets, exfil channels |
| 8 | **Dynamics** | Tick-based time, world events, NPC actors, stealth system |

---

## §8 Module System

Universal extension contract. Every engine capability is a module.

```typescript
interface Module {
    readonly id: string
    readonly type: string               // open union — any string
    readonly version: string
    readonly description: string
    readonly provides: Capability[]
    readonly requires: Capability[]
    init(context: SimulationContext): void
    destroy(): void
    onTick?(tick: number): void          // per-tick updates
    onPause?(): void                     // pause hooks
    onResume?(): void                    // resume hooks
}
```

Module types (well-known + open):
- `lens` — UI view
- `engine` — simulation logic
- `dynamics` — world events
- `service` — network service
- `defense` — detection/prevention
- `actor` — NPC behavior
- `surface` — attack surface
- Any string — third-party modules

Modules cannot access each other directly. Communication flows
through the `EventBus`. Modules receive `SimulationContext` which
is **read-only** — they cannot mutate the simulation state directly.

---

## §9 Event System

Typed event bus with prefix-based subscription.

```typescript
interface EventBus {
    emit(event: EngineEvent): void
    on(type: string, handler: EventHandler): Unsubscribe
    onPrefix(prefix: string, handler: EventHandler): Unsubscribe
}
```

Event categories: `sim:`, `fs:`, `net:`, `auth:`, `objective:`,
`service:`, `dynamics:`, `custom:`.

The `custom:` prefix is open — third-party packages use it.

---

## §10 Services

Implemented services:

| Service | Transport | Implementation |
|---|---|---|
| **HTTP** | TCP | Route-based, configurable responses, static/dynamic |
| **SSH** | TCP | Auth against VFS shadow/authorized_keys, brute-force lockout, auth.log |
| **SMTP** | TCP | Inbox management, phishing detection, Maildir VFS, mail.log |
| **DNS** | UDP | A/AAAA/MX/TXT/NS/SOA/PTR/CNAME/SRV, wildcard, AXFR zone transfer |
| **Search** | HTTP | Simulated search engine for VARIANT Internet |

Service handler contract:

```typescript
interface ServiceHandler {
    name: string
    port: number
    protocol: 'tcp' | 'udp'
    start(ctx: ServiceContext): void
    handle(request: ServiceRequest, ctx: ServiceContext): ServiceResponse | null
    stop(): void
}
```

---

## §11 Dynamics Engine

Executes timed and reactive world changes. Version 2.0.

**Action types:**

| Action | What It Does |
|---|---|
| `spawn-process` | Add a background process to a VM |
| `modify-file` | Change a file on a VM |
| `alert` | Display a message to the player |
| `rotate-credential` | Change a credential value |
| `send-email` | Deliver an email (triggers mail system) |
| `npc-action` | Trigger an NPC behavior |
| `start-service` | Start a service on a machine |
| `stop-service` | Stop a service on a machine |
| `inject-traffic` | Generate network traffic |
| `open-lens` | Open a UI lens for the player |
| `custom` | Delegate to DynamicActionHandlerRegistry |

**Features:**
- Repeating timed events (`repeatInterval`)
- Once-firing reactive events (`once: true`)
- Custom action handler registry (extensible, append-only)

---

## §12 NPC System

Simulates other users — admins, employees, attackers, service accounts.
Their activity appears in logs, process lists, and file modifications.

**NPC action types:**
| Action | Kind | What It Does |
|---|---|---|
| Login | `login` | SSH/console/su with success/failure |
| Logout | `logout` | Session end |
| Command | `command` | Shell command (log or execute) |
| File Modify | `file-modify` | Create/append/replace/delete files |
| Log | `log` | Write to log files |
| Alert | `alert` | Message to player |
| Attack | `attack` | Named attack with log entries |
| Send Email | `send-email` | Phishing, social engineering |
| Network | `network` | Scan, connect, transfer, exfiltrate |
| Custom | `custom` | Third-party actions |

**NPCRole** is an open union — any string accepted. Well-known:
`admin`, `employee`, `attacker`, `service-account`. Custom:
`'threat-actor'`, `'soc-analyst'`, `'vendor/custom-role'`.

**NPC Template Registry:** Pre-built behavior templates registered
by third-party packages.

---

## §13 Objective Evaluation

Pluggable objective evaluation via `ObjectiveEvaluatorRegistry`.

**Built-in evaluators:**

| Evaluator ID | What It Detects |
|---|---|
| `detect-file-read` | Player reads a specific file on a specific machine |
| `detect-command` | Player executes a command matching a regex pattern |
| `detect-traffic` | Specific network traffic between machines |
| `collect-items` | N items matching a pattern collected |
| `survive-clean` | Survive N ticks without triggering a failure event |
| `phishing-detection` | Player correctly flags malicious emails |

Custom evaluators register via the registry. They receive read-only
context and report progress/completion. They cannot mutate the sim.

---

## §14 Credential System

Credentials are attack graph edges. Found at one location, valid
at another.

Types: `password`, `ssh-key`, `api-token`, `jwt-secret`,
`database-password`, `cookie`, `certificate`.

The CredentialGraph runtime manages discovery, validation, rotation,
indexing by target and location, constant-time comparison, and
auto-discovery via filesystem event triggers.

---

## §15 INVARIANT Bridge

Connection between the game and production defense.

| Access Level | What's Available |
|---|---|
| Community levels | Codebase library, all images, all primitives, known patterns |
| Curated levels | + real payloads from sensors, daily challenges from live telemetry |

```typescript
interface InvariantBridge {
    getPayloads(vulnClass: string): Promise<Payload[]>
    testRule(rule: ISLRule, payloads: Payload[]): Promise<RuleTestResult>
    submitRule(rule: ISLRule, result: RuleTestResult): Promise<SubmissionResult>
    getPortfolio(playerId: string): Promise<RulePortfolio>
}
```

This is the **only part of the system that requires a server.** The
game plays fully without it.

---

## §16 What's Missing — Gap Analysis

For a fully realistic security environment with complete offensive
and defensive simulation, these subsystems are not yet implemented:

### §16.1 Identity & Access Systems

| System | Status | Why It Matters |
|---|---|---|
| **Active Directory / LDAP** | ❌ Not built | Kerberoasting, Golden Ticket, DCSync, Group Policy abuse. THE core of enterprise networks. |
| **OAuth/SAML/SSO provider** | ❌ Not built | Token theft, redirect manipulation, scope escalation. Cloud identity attacks. |
| **MFA simulation** | ❌ Not built | MFA bypass, push fatigue, SIM swap, authenticator TOTP. |
| **PAM/sudo policy engine** | ❌ Not built | Privilege escalation via misconfigured sudo, SUID, capabilities. |

### §16.2 Network & Infrastructure

| System | Status | Why It Matters |
|---|---|---|
| **Firewall rule engine** | 🟡 Types defined, no evaluation | iptables simulation, misconfiguration detection. |
| **VPN/tunnel simulation** | ❌ Not built | VPN pivoting, split tunneling, tunnel over DNS/ICMP. |
| **Load balancer / reverse proxy** | ❌ Not built | Request smuggling, header injection, backend exposure. |
| **WAF simulation** | ❌ Not built | WAF bypass training, rule writing. |
| **Packet capture engine** | ❌ Not built | pcap replay, traffic analysis, MITM detection. |
| **ARP/Layer 2** | ❌ Not built | ARP spoofing, MITM at Layer 2, VLAN hopping. |

### §16.3 Monitoring & Detection (Blue Team)

| System | Status | Why It Matters |
|---|---|---|
| **SIEM / log aggregation** | ❌ Not built | SOC analyst training. Log correlation, alert triage. |
| **IDS/IPS rules engine** | ❌ Not built | Snort/Suricata rule writing, evasion techniques. |
| **EDR simulation** | ❌ Not built | Process monitoring, behavioral detection, response. |
| **Audit log system** | ❌ Not built | Compliance logging, forensic timeline. |
| **Alert correlation engine** | ❌ Not built | Multi-source alert correlation, false positive tuning. |

### §16.4 Cloud & Container

| System | Status | Why It Matters |
|---|---|---|
| **Cloud console (AWS/GCP/Azure)** | 🟡 Lens defined, no service | IAM misconfiguration, S3 bucket exposure, metadata service. |
| **Container runtime** | ❌ Not built | Container escape, image poisoning, registry attacks. |
| **Kubernetes API** | ❌ Not built | RBAC abuse, pod security, secret exposure. |
| **Serverless simulation** | ❌ Not built | Lambda cold start, event injection. |

### §16.5 Endpoint & Forensics

| System | Status | Why It Matters |
|---|---|---|
| **Process tree** | 🟡 ProcessSpec exists, no hierarchy | Process lineage for forensics, orphan detection. |
| **Memory simulation** | ❌ Not built | Memory forensics, credential dumping, heap spray. |
| **Disk forensics** | ❌ Not built | Deleted file recovery, timeline analysis. |
| **Registry/config store** | ❌ Not built | Windows-style persistence, config tampering. |

### §16.6 Application Security

| System | Status | Why It Matters |
|---|---|---|
| **SQL query evaluator** | 🟡 Engine exists in INVARIANT, not integrated | Real SQL evaluation for injection training. |
| **Certificate/TLS system** | ❌ Not built | Certificate pinning, HTTPS interception, CA spoofing. |
| **JWT evaluator** | 🟡 Engine exists in INVARIANT | Token manipulation, algorithm confusion, signature bypass. |
| **Deserialization engine** | ❌ Not built | Object injection, gadget chains. |

### §16.7 Social Engineering & Physical

| System | Status | Why It Matters |
|---|---|---|
| **Phishing campaign engine** | ✅ SMTP + mail spec | Multi-wave phishing, spear phishing, credential harvesting. |
| **Vishing simulation** | ❌ Not built | Phone-based social engineering. |
| **Physical access** | ❌ Not built | Badge cloning, USB drops, rogue AP. |
| **Supply chain** | 🟡 Package mirror exists | Dependency confusion, typosquatting, build injection. |

### §16.8 Persistence & C2

| System | Status | Why It Matters |
|---|---|---|
| **Persistence mechanism engine** | ❌ Not built | Cron, systemd, SSH keys, web shells, backdoors — detection and creation. |
| **C2 framework simulation** | 🟡 VARIANT Internet has C2 type | Beacon callbacks, staged payloads, encrypted channels. |
| **Lateral movement engine** | ❌ Not built | Pass-the-hash, WMIC, PsExec, SSH pivoting |
| **Data exfiltration channels** | ❌ Not built | DNS tunneling, ICMP covert, steganography. |

### §16.9 Priority Build Order

Based on impact × difficulty, the next systems to build:

1. **Firewall rule evaluation engine** — evaluate iptables rules against traffic
2. **Process tree hierarchy** — real parent/child relationships for forensics
3. **SIEM/log aggregation service** — SOC analyst training
4. **Active Directory/LDAP service** — enterprise identity attacks
5. **Certificate/TLS system** — HTTPS, cert chains, MITM
6. **SQL query evaluator integration** — bridge INVARIANT engine
7. **Persistence mechanism catalog** — cron/systemd/webshell detection
8. **Packet capture engine** — traffic analysis training
9. **IDS rule engine** — Snort/Suricata rule writing
10. **Cloud console service** — AWS/GCP IAM training

---

## §17 VARIANT Invariants

Things that must never change regardless of what we build on top:

1. **All gameplay runs in the browser.** Zero server compute.
2. **WorldSpecs are pure data.** No functions, no callbacks, no code.
3. **Backends are composable and swappable.** Level designers choose per machine.
4. **Network isolation cannot be disabled.** No flag, no config, no override.
5. **Modules never touch core.** Adding any capability requires zero core changes.
6. **Query engines are shared with INVARIANT.** Same evaluation code.
7. **Players are never constrained to intended solutions.** Honest mechanics.
8. **Defense rules authored in VARIANT can reach production.** Real impact.
9. **Responsible escape.** Reward disclosure, take responsibility.
10. **Everything starts from the terminal.**
11. **Lenses are unlimited.** Any number of views.
12. **INVARIANT payloads are privileged.** Community can't access live data.
13. **Level designers create worlds, not UIs.**
14. **All open source dependencies are permissively licensed.**
15. **Every system is a registry.** Append-only, frozen, namespaced, substitutable.
16. **Every interface is designed for decades.** Open unions, extension fields, backward compatibility.

---

## §18 System Diagram

```
┌───────────────────────────────────────────────────────────────────┐
│  PLAYER'S BROWSER TAB (the entire universe)                       │
│                                                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  VM RUNTIME (BackendRouter)                                  │  │
│  │                                                               │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐               │  │
│  │  │ VM 1       │ │ Simulacrum │ │ Sim+       │  ...N         │  │
│  │  │ Alpine     │ │ web-01     │ │ db-01      │               │  │
│  │  │ player     │ │ HTTP/SSH   │ │ SSH+MySQL  │               │  │
│  │  │ NE2K NIC ──│─│─ lwIP ─────│─│─ lwIP ─────│── Ethernet   │  │
│  │  └────────────┘ └────────────┘ └────────────┘    frames     │  │
│  │         │              │              │                       │  │
│  │  ┌──────▼──────────────▼──────────────▼──────────────────┐   │  │
│  │  │  NETWORK FABRIC (JavaScript)                           │   │  │
│  │  │  Ethernet routing · DNS · Firewall · NAT               │   │  │
│  │  │  VARIANT Internet (cloud, DNS, repos, C2)              │   │  │
│  │  │  ⛔ ZERO PATH TO REAL INTERNET                         │   │  │
│  │  └────────────────────────────────────────────────────────┘   │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  LENS LAYER (React Compositor)                               │  │
│  │  Terminal · Browser · Email · NetMap · PCAP · DB · Defense  │  │
│  │  File Manager · Code Editor · Cloud Console · Custom        │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  ENGINE LAYER                                                │  │
│  │  WorldSpec → Event Bus → Module System → Registries         │  │
│  │  Dynamics Engine · Objective Evaluator · Scoring Engine      │  │
│  │  Credential Graph · NPC System · Resource Estimator          │  │
│  │  Query Engines (SQL, Shell, JWT, Template, XML, Path, ...)  │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ⚡ ALL = JAVASCRIPT/WASM IN ONE BROWSER TAB                      │
│  📦 CDN: v86 binary, disk images, WorldSpecs, assets              │
│  🔌 Optional: INVARIANT bridge, score submission, profiles        │
└───────────────────────────────────────────────────────────────────┘
```

---

## §19 Build Phases

| Phase | Description | Deliverable |
|---|---|---|
| **1: Single VM** | v86 + xterm.js. Boot Alpine. VFS overlay. Basic WorldSpec. | Real Linux in the browser. |
| **2: Network** | Fabric, DNS, firewall, multi-machine, credential graph. | Lateral movement. |
| **3: Web Exploitation** | Browser lens, query engines, web services, codebase library. | Full web exploitation. |
| **4: Advanced** | VARIANT Internet, email, NPC actors, dynamics, stealth. | Phishing, supply chain, cloud. |
| **5: Defense** | Defense dashboard, ISL authoring, INVARIANT bridge, portfolio. | The talent pipeline is real. |
| **6: Community** | Daily challenge, streaks, level editor, publishing, leaderboards. | The Roblox flywheel is real. |

---

## §20 Current Implementation Status

| Subsystem | Status | Files |
|---|---|---|
| WorldSpec types | ✅ Complete | `core/world/types.ts` |
| WorldSpec validator | ✅ Complete | `core/world/validator.ts` |
| Event bus | ✅ Complete | `core/event-bus.ts`, `core/events.ts` |
| Module system | ✅ Complete | `core/modules.ts` |
| Engine orchestrator | ✅ Complete | `core/engine.ts` |
| Network fabric | ✅ Complete | `core/fabric.ts` |
| Frame parser | ✅ Complete | `core/frames.ts` |
| Backend router | ✅ Complete | `backends/backend-router.ts` |
| Simulacrum backend | ✅ Complete | `backends/simulacrum.ts` |
| VFS | ✅ Complete | `lib/vfs/` |
| Shell (ScriptedShell) | ✅ Complete | `lib/shell/` |
| Credential graph | ✅ Complete | `lib/creds/` |
| Log system | ✅ Complete | `lib/logs/` |
| Vuln injection | ✅ Complete | `lib/vuln/` |
| Package manager | ✅ Complete | `lib/packages/` |
| Database simulation | ✅ Complete | `lib/database/` |
| NPC system | ✅ Complete | `lib/npc/` |
| HTTP service | ✅ Complete | `lib/services/http-service.ts` |
| SSH service | ✅ Complete | `lib/services/ssh-service.ts` |
| SMTP service | ✅ Complete | `lib/services/smtp-service.ts` |
| DNS service | ✅ Complete | `lib/services/dns-service.ts` |
| Search engine | ✅ Complete | `lib/services/search-engine.ts` |
| Service factory | ✅ Complete | `lib/services/factory.ts` |
| Protocol handler registry | ✅ Complete | `lib/services/protocol-handler.ts` |
| Resource estimator | ✅ Complete | `lib/resource-estimator.ts` |
| Dynamics engine v2 | ✅ Complete | `modules/dynamics-engine.ts` |
| Objective detector | ✅ Complete | `modules/objective-detector.ts` |
| Objective evaluator registry | ✅ Complete | `modules/objective-evaluators.ts` |
| Filesystem monitor | ✅ Complete | `modules/fs-monitor.ts` |
| Network monitor | ✅ Complete | `modules/network-monitor.ts` |
| Game over detector | ✅ Complete | `modules/gameover-detector.ts` |
| Scoring engine | ✅ Complete | `modules/scoring-engine.ts` |
| VARIANT Internet | ✅ Complete | `modules/variant-internet.ts` |
| Lens types | ✅ Complete | `ui/lens/types.ts` |
| Compositor state | ✅ Complete | `ui/lens/compositor-state.ts` |
| Compositor React | 🟡 Scaffolded | `ui/lens/compositor.tsx` |
| Terminal lens | 🟡 Scaffolded | `ui/terminal/` |

**Test coverage:** 417 tests across 25 test files. All pass.
