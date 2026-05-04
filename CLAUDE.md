# provas — agent-facing canonical context

> **Read [`README.md`](./README.md) first**, then
> [`cartorio/docs/COMPLIANCE-PROOF.md`](https://github.com/pleme-io/cartorio/blob/main/docs/COMPLIANCE-PROOF.md)
> for the wider proof model. This file covers invariants and
> operational rules specific to provas.

## What provas is

The typed compliance-test framework. Compliance tests become *part
of the merkle ledger* by construction: running a `Pack` produces a
deterministic `pack_hash` that anyone can re-derive from the same
target + same pack version. Cartorio stores the hash; verifiers
re-derive it; the chain of trust is constructive.

## Architectural invariants — DO NOT BREAK

1. **Tests are pure functions of the target.** A test must produce
   the same outcome for the same input, forever. NO `now()`, NO PRNG,
   NO env reads, NO network. A non-deterministic test silently
   breaks the proof — verifier and publisher can disagree on
   `pack_hash` even running the same pack against the same bytes.
   This is enforced socially today; will be enforced by a clippy
   lint or runtime sandbox in vNext.

2. **`pack_hash` is domain-separated and stable.** The encoding in
   `runner::pack_hash()` is:
   ```
   "provas-pack-v1\0" || pack_id || \0 || pack_version || \0 ||
     for each run: test_id || \0 || test_version || \0 ||
       (Pass{None}      → "pass\0"      |
        Pass{Some(e)}   → "pass-with\0" || e || \0 |
        Fail{reason}    → "fail\0" || reason || \0)
   ```
   Changing this breaks every recorded compliance proof in cartorio.
   Don't.

3. **`Pack.tests` order is part of the proof.** Reordering tests
   changes the hash (proven by `pack_hash_changes_when_runs_reordered`
   property test). Don't reorder for cosmetic reasons; treat the
   pack's test list as append-only.

4. **`Target` enum variants are append-only.** New artifact kinds
   add new `Target` variants; existing variants stay. Tests written
   against `Target::OciManifest` keep working when `Target::Bundle`
   is added.

5. **Evidence is part of the hash.** `Pass { evidence: Some(_) }`
   yields a different hash than `Pass { evidence: None }`. This is
   load-bearing for bundle proofs (which emit member identities as
   evidence). The `pass()` constructor explicitly sets `None`; use
   `pass_with(s)` to attach.

## When adding a new pack

1. **One file per domain** in `src/tests_<domain>.rs`. Each test is
   a struct implementing `ComplianceTest`. Test ids namespace by
   domain (`oci.foo`, `helm.bar`, `bundle.baz`).

2. **Cite the NIST 800-53 control** in the test's doc-comment. e.g.
   `/// CM-2 (baseline configuration) — manifest schemaVersion is 2.`
   This is non-optional. Auditors trace from a failing test to the
   requirement it enforces by reading these comments.

3. **Add a positive test + at least one negative test** per
   `ComplianceTest` impl. Positive: known-good target → Pass.
   Negative: known-violation target → Fail with reason matching the
   expected substring.

4. **Add to a Pack** in `src/lib.rs`. Pack declarations are the
   public surface; renaming a pack (changing `id` or `version`) is
   a breaking change to every consumer that references it.

5. **Add a positive test** that runs the entire pack against a
   known-good target and asserts `result.all_passed`.

6. **For new packs targeting real artifacts**: add a test in
   `tests/all_real_openclaw_charts.rs` (or analog) that embeds the
   real artifact at compile time via `include_str!`. This catches
   real production violations the moment they enter the codebase.

## Property-based tests

`tests/properties.rs` exercises the 9 load-bearing invariants of
`pack_hash` via proptest. Adding a new property:

- Pick the invariant in plain English ("changing X must change the
  hash").
- Write a `proptest!` test that randomly samples the relevant inputs
  and asserts the property.
- Use `prop_assume!` to filter degenerate cases.

## Real-chart sweep

`tests/all_real_openclaw_charts.rs` embeds every real `lareira-openclaw-*`
chart at compile time. CI gate: chart drift that introduces a
violation breaks the build. When adding new lareira charts, add a
matching test entry.

## provas-verify CLI

`src/bin/verify.rs` is the standalone verifier. Today supports OCI
image and helm-as-OCI manifest packs. Bundle and helm-content packs
require structured target construction (separate Chart.yaml +
values.yaml + templates), not yet wired up — documented as a follow-on.

## Companion repos

See [`README.md`](./README.md) for the four-repo decomposition.
Cartorio mirrors `TestRun` + `TestOutcome` in its wire format; if
the provas types change shape, **cartorio's mirrored types must
change too** to keep wire compatibility.
