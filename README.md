# VARIANT — Full-Spectrum Security Simulation Engine

> **The top-of-funnel growth engine.** A browser-based engine that boots real Linux machines via WebAssembly, connects them through an air-gapped virtual network, and powers real vulnerability mechanics with the same query engines that run INVARIANT's production defense.

**Live:** [santh.io/terminal](https://santh.io/terminal)

## What This Is

VARIANT is a composable security world simulator. Level authors write JSON (WorldSpec). The engine interprets it honestly — booting v86 VMs, wiring networks, and running vulnerability mechanics. Everything runs in the player's browser tab. Zero server compute.

INVARIANT identifies the mathematical property underneath an attack. VARIANT generates the space in which that property manifests. The query engines are shared — the same code powers both.

## Stack

- **Framework:** React + Vite + TypeScript
- **VM:** v86 (BSD-2, x86 emulation in WebAssembly)
- **Terminal:** xterm.js (MIT)
- **Hosting:** Cloudflare Pages (static only)
- **Testing:** Vitest

## Structure

```
variant/
├── src/
│   ├── core/              # Stable — VM backend, network fabric, WorldSpec, events
│   ├── lib/               # Shared types, registries, NPC system
│   ├── modules/           # Extensible — lenses, engines, services, actors, defenses
│   ├── bridge/            # INVARIANT integration (payloads, ISL rules, portfolio)
│   ├── meta/              # Objectives, scoring, daily challenge, streaks
│   ├── ui/                # React shell (hosts lenses)
│   └── levels/            # Level definitions (pure JSON WorldSpecs)
├── tests/
├── ARCHITECTURE.md        # → Points to vision.md §11
└── VARIANT.md             # → Points to vision.md §11
```

## Key Constraints

- **100% client-side.** All gameplay runs in the browser. Zero server compute.
- **Air-gapped.** VMs cannot reach the real internet. Triple isolation enforced.
- **WorldSpecs are pure data.** No functions, no callbacks, no code.
- **Chromebook floor.** Beginner levels must run on 4GB school Chromebooks.
- **Terminal first.** Every level starts in a terminal. Lenses open from commands.

## Development

```bash
npm install
npm run dev              # localhost:5173
npm test                 # vitest
```

## Architecture Reference

See [vision.md §11](../vision.md) for the complete architecture including:
- Foundational constraints (§11.2)
- Composable backends: Simulacrum → v86 → CheerpX (§11.3)
- Lens system (§11.4)
- 9-layer primitive taxonomy (§11.6)
- Core contracts (§11.7)
- INVARIANT bridge (§11.8)
- Build phases (§11.15)
