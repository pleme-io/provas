# provas

Typed compliance-test framework. Compliance tests become *part of the
merkle ledger* by construction: running a `Pack` produces a deterministic
`pack_hash` that anyone can re-derive from the same target + same pack
version. Cartorio stores the hash; verifiers re-derive it; the chain
of trust is constructive (no trust in pleme-io required).

## Core types

```rust
trait ComplianceTest: Send + Sync {
    fn id(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn run(&self, target: &Target) -> TestOutcome;
}

enum Target {
    OciManifest  { bytes: Vec<u8> },
    HelmManifest { bytes: Vec<u8> },
    Bundle       { members: Vec<BundleMember> },
}

enum TestOutcome {
    Pass { evidence: Option<String> },  // evidence carried into pack_hash
    Fail { reason: String },
}

struct Pack {
    pub id: String,        // e.g. "fedramp-high-openclaw-image"
    pub version: String,   // e.g. "1"
    pub tests: Vec<Box<dyn ComplianceTest>>,
}

// Runner::run_pack(pack, target) -> PackResult { runs, pack_hash, all_passed }
// pack_hash = blake3 over pack_id || pack_version || canonical(test outcomes)
```

The `pack_hash` function is **deterministic + domain-separated**.
Reordering tests, changing the pack id, changing the pack version,
changing any individual test outcome, or changing evidence in a
`Pass { evidence: Some(_) }` all change the hash. That's the proof
property: same hash → same pack ran the same tests in the same order
against the same target with the same outcomes.

## Curated packs (FedRAMP-High openclaw)

| Pack | Target | Tests |
|---|---|---|
| `fedramp-high-openclaw-image@1` | `OciManifest` | 6 — schema, media type, config sha256, layer pinning, manifest size, slsa annotation |
| `fedramp-high-openclaw-helm@1` | `HelmManifest` | 5 — schema, helm config media type, config sha256, layer pinning, helm layer media types |
| `fedramp-high-openclaw-bundle@1` | `Bundle` | 4 — has image member, has chart member, distinct digests, non-zero member pack_hashes |

Bundle tests emit member `digest:pack_hash` as evidence on pass, so
the bundle's pack_hash inherits from its members' proofs — swapping a
member changes the bundle hash deterministically.

## Adding a pack

1. Create `src/tests_<domain>.rs` with one struct per test, each
   implementing `ComplianceTest`. Tests must be **pure functions of the
   target** — no `now()`, no PRNG, no env, no network. Same target →
   same outcome forever.

2. Compose into a `Pack` in `src/lib.rs`:
   ```rust
   #[must_use]
   pub fn fedramp_moderate_my_thing_v1() -> Pack {
       Pack {
           id: "fedramp-moderate-my-thing".into(),
           version: "1".into(),
           tests: vec![Box::new(MyTest1), Box::new(MyTest2)],
       }
   }
   ```

3. Add a unit test verifying a known-good target passes every test in
   the pack (`good_target_passes_every_test_in_pack`).

4. Optionally: register in tabeliao's `pack_by_name` so the publish
   CLI can enforce it via `--pack <pack_id>@<version>`.

## Determinism

Tests are pure functions. Determinism is non-negotiable; a
non-deterministic test silently breaks the proof — the verifier and
publisher can disagree on `pack_hash` even when both ran the same
pack against the same bytes. CI verifies this property by:

- Running the same pack twice against the same target and asserting
  byte-identical `PackResult.pack_hash`.
- Running the pack against semantically-equivalent-but-byte-different
  inputs (trailing whitespace, key order) and asserting the
  `pack_hash` is invariant under JSON parse normalization.

## Compliance proof — see canonical doc

For the broader concept (transferable, mechanically-verifiable
compliance receipts and how packs slot into the cartorio + lacre
gate), read
[`cartorio/docs/COMPLIANCE-PROOF.md`](https://github.com/pleme-io/cartorio/blob/main/docs/COMPLIANCE-PROOF.md).

## Status

Reference impl. v0.2.0. 31 tests, 0 clippy warnings.
