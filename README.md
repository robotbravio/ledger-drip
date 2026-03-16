# DRIP — Decentralized Research & Identity Protocol

DRIP is a **hardware-backed decentralized identity and artifact-signing protocol** for researchers, developers, and security workflows, using Ledger as the root of trust.


## Working MVP CLI (implemented)

This repository now includes a runnable DRIP MVP CLI in `src/drip/cli.py`.

### Capabilities

- initialize local DRIP state (`drip init`),
- create/show a local identity (`drip identity create`, `drip identity show`),
- sign files into portable proof bundles (`drip sign-file`),
- verify files against proof bundles (`drip verify-file`).

### Quickstart

```bash
python -m pip install -e .
drip init
drip identity create alice
drip sign-file ./report.md --identity alice --artifact-type vuln-report --out ./report.proof.json
drip verify-file ./report.md --proof ./report.proof.json
```

> Note: this MVP uses local software keys via OpenSSL for development flow simulation. Ledger hardware transport/signing integration is the next step.

## Why DRIP exists

Modern security and software workflows depend on signatures, but most signatures are still generated from software keys on laptops, CI agents, or cloud services. DRIP aims to improve this by making a Ledger device the root signing authority for identity and artifact proofs.

DRIP is designed to provide:

- **Authorship proof** — establish who created an artifact.
- **Integrity proof** — detect post-signing tampering.
- **Time anchoring** — optionally anchor proof references on chain.
- **Identity continuity** — support key rotation/revocation/recovery.
- **Portable trust** — package verification material as proof bundles.

## Project framing

DRIP is not intended to be a coin wallet. It is better understood as a combination of:

- a hardware identity card,
- a signing/notary workflow,
- a verification engine,
- an optional blockchain timestamp layer,
- and (later) a credential/reputation graph.

## Core rule

> **All secret operations happen on Ledger; all complex orchestration happens off-device.**

That means:

- The device app handles key operations and trusted confirmations.
- Companion tools (CLI/desktop/mobile) handle parsing, hashing, canonicalization, networking, and storage.

## System components

### 1) Ledger device app

Security-sensitive, minimal scope:

- derive/export identity public key material,
- sign digest of canonical payloads,
- approve/reject on trusted screen,
- support key lifecycle operations (rotation/revocation/recovery confirmations).

### 2) Companion app / local CLI

User and automation interface:

- compute artifact hashes,
- build canonical signing payloads,
- request Ledger signatures,
- generate/export proof bundles,
- verify signatures + identity/key history,
- optionally submit/retrieve chain anchors.

### 3) SDKs

Shared libraries for integrations (TypeScript/Python/Rust suggested):

- hashing + canonical serialization,
- Ledger transport wrappers,
- DID document handling,
- proof bundle generation and verification,
- key lifecycle resolution logic.

### 4) Optional chain anchoring

Store only minimal references (never sensitive artifacts):

- digest/reference hash,
- signer DID reference,
- proof type,
- timestamp via chain inclusion.

### 5) Verification services/integrations

Verifier outputs should be human-readable and timeline-aware:

- signature validity,
- signer identity resolution,
- key validity at signing time,
- revocation/rotation impacts,
- optional anchor confirmation.

## Identity model (DID-oriented)

A DRIP identity should include:

- one primary Ledger-backed signing key,
- a DID (`did:drip:<network>:<id>` style),
- optional linked/recovery keys,
- lifecycle history (rotation/revocation/recovery events),
- optional service endpoints and attestations.

## Artifact signing model

Artifacts can include reports, PoCs, releases, tags, SBOMs, and API payloads.

DRIP should sign **structured payloads** (canonicalized), not context-free raw file hashes.

Recommended payload fields:

- protocol version,
- artifact type,
- hash algorithm,
- digest,
- signer DID/key reference,
- creation timestamp,
- optional context and predecessor references.

## Proof bundles

Proof bundles make verification portable across tools and time.

Suggested bundle contents:

- canonical payload,
- signature,
- signer DID/key reference,
- digest + hash algorithm,
- signed timestamp,
- optional chain anchor refs,
- optional credential refs.

## Key lifecycle requirements

DRIP must support continuity and incident response:

- **Rotation:** old→new key transition signed by both keys.
- **Revocation:** explicit event making a key untrusted.
- **Compromise notice:** timeline marker affecting trust decisions.
- **Recovery:** policy-driven workflow (e.g., M-of-N approvals).

Verification should always evaluate validity in time context (key active at signing time vs current state).

## Security and privacy principles

- Treat Ledger screen confirmations as the trusted UX surface.
- Keep device prompts concise and stable (operation + digest/key fingerprints).
- Never anchor sensitive plaintext content on chain.
- Support pseudonymous identity mode by default.
- Enable compartmentalized identities for different domains/workstreams.

## MVP scope (build this first)

### MVP goals

1. Ledger device app skeleton:
   - export identity public key,
   - sign canonical artifact payload hash.
2. CLI/companion flow:
   - create identity metadata,
   - sign local files,
   - verify signatures,
   - export proof bundles.
3. Optional simple EVM anchor:
   - emit digest + DID reference + timestamped event.
4. Basic key rotation event support.

### MVP artifact types

- generic file,
- vulnerability report,
- release artifact.

## Recommended phased delivery

### Phase 1 — Protocol/data model

- JSON schemas for identity/proofs/events,
- canonical serialization rules,
- proof bundle format,
- verification rules.

### Phase 2 — CLI

- `identity create/show`,
- `sign file`,
- `verify file`,
- `bundle export`.

### Phase 3 — Companion/SDK internals

- Ledger transport wrapper,
- APDU command encode/decode,
- local state handling.

### Phase 4 — Device app skeleton

- app init + command dispatch,
- public key export,
- sign digest flow,
- trusted-screen confirmations.

### Phase 5 — Anchor + resolver integration

- minimal anchor contract/events,
- anchor client,
- verifier lookup/resolution.

## Long-term expansion

After core signing and verification are stable:

- API challenge signing,
- Git/release/container/SBOM integrations,
- credential issuance/presentation,
- reputation event graph,
- richer recovery UX,
- optional hardware attestation references.

## Proposed monorepo layout

```text
drip/
  apps/
    desktop/
    cli/
  packages/
    core/
    sdk-ts/
    sdk-python/
    verifier/
    did/
    proofs/
    anchors/
  ledger/
    device-app/
    transport/
    apdu-spec/
  contracts/
    evm/
  docs/
    architecture/
    protocol/
    threat-model/
    api/
  examples/
    sign-report/
    sign-release/
    verify-proof/
```
