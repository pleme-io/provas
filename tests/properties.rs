//! Property-based tests for the provas core invariants.
#![allow(clippy::doc_markdown, clippy::redundant_closure)]
//!
//! These complement the targeted unit tests by sweeping random inputs
//! and asserting the proof framework's load-bearing properties hold
//! over the entire input space (within reason).
//!
//! Properties tested:
//!   1. **Determinism**: same pack + same target → byte-identical pack_hash.
//!      This is the property that makes the proof transferable; a
//!      verifier re-running the pack must get the same hash.
//!   2. **Sensitivity**: changing any test outcome changes the pack_hash.
//!      A failing test that "looks like" a passing test in the recorded
//!      hash would break tamper-evidence.
//!   3. **Order-sensitivity**: reordering tests changes the pack_hash.
//!      Tests must run in pack-declared order; reordering attacks fail.
//!   4. **Pack identity**: changing pack_id or pack_version changes the
//!      pack_hash. Two distinct packs with identical test outcomes are
//!      not equivalent receipts.
//!   5. **Evidence sensitivity**: a Pass with evidence X yields a
//!      different hash than a Pass with evidence Y. (This is the
//!      mechanism by which bundle proofs inherit member identities.)

use proptest::prelude::*;

use provas::runner::{TestOutcome, TestRun, pack_hash};

fn arb_test_id() -> impl Strategy<Value = String> {
    "[a-z]{1,8}\\.[a-z_]{1,16}"
}

fn arb_outcome() -> impl Strategy<Value = TestOutcome> {
    prop_oneof![
        Just(TestOutcome::pass()),
        ".{0,32}".prop_map(|e| TestOutcome::pass_with(e)),
        ".{0,64}".prop_map(|r| TestOutcome::fail(r)),
    ]
}

fn arb_test_run() -> impl Strategy<Value = TestRun> {
    (arb_test_id(), "[0-9]{1,3}", arb_outcome()).prop_map(|(id, ver, outcome)| TestRun {
        test_id: id,
        test_version: ver,
        outcome,
    })
}

fn arb_runs() -> impl Strategy<Value = Vec<TestRun>> {
    prop::collection::vec(arb_test_run(), 0..16)
}

proptest! {
    /// 1. Determinism: same inputs → same hash. This is the
    ///    transferable-proof property: any verifier with the same
    ///    pack code + target re-derives the same hash.
    #[test]
    fn pack_hash_is_deterministic(
        pack_id in "[a-z-]{1,32}",
        pack_version in "[0-9]{1,3}",
        runs in arb_runs(),
    ) {
        let h1 = pack_hash(&pack_id, &pack_version, &runs);
        let h2 = pack_hash(&pack_id, &pack_version, &runs);
        prop_assert_eq!(h1, h2);
    }

    /// 2. Pack identity matters: two packs with the same runs but
    ///    different ids yield different hashes.
    #[test]
    fn pack_hash_changes_with_pack_id(
        pack_id_a in "[a-z]{1,16}",
        pack_id_b in "[a-z]{1,16}",
        pack_version in "[0-9]{1,3}",
        runs in arb_runs(),
    ) {
        prop_assume!(pack_id_a != pack_id_b);
        let h_a = pack_hash(&pack_id_a, &pack_version, &runs);
        let h_b = pack_hash(&pack_id_b, &pack_version, &runs);
        prop_assert_ne!(h_a, h_b);
    }

    /// 3. Pack version matters: same id + same runs but different
    ///    versions yield different hashes.
    #[test]
    fn pack_hash_changes_with_pack_version(
        pack_id in "[a-z-]{1,32}",
        ver_a in "[0-9]{1,3}",
        ver_b in "[0-9]{1,3}",
        runs in arb_runs(),
    ) {
        prop_assume!(ver_a != ver_b);
        let h_a = pack_hash(&pack_id, &ver_a, &runs);
        let h_b = pack_hash(&pack_id, &ver_b, &runs);
        prop_assert_ne!(h_a, h_b);
    }

    /// 4. Order-sensitivity: reordering test runs changes the hash.
    ///    Reordering attacks (e.g. "swap a Fail to where another Pass
    ///    was") must change the recorded hash so verifiers detect.
    #[test]
    fn pack_hash_changes_when_runs_reordered(
        pack_id in "[a-z-]{1,32}",
        pack_version in "[0-9]{1,3}",
        runs in prop::collection::vec(arb_test_run(), 2..10),
    ) {
        // Build a reversed copy.
        let mut reversed = runs.clone();
        reversed.reverse();
        // Skip palindromic cases (rare but exist for length-1 vecs we
        // already filtered, length-2 with identical entries, etc).
        prop_assume!(reversed != runs);
        let h_normal = pack_hash(&pack_id, &pack_version, &runs);
        let h_reversed = pack_hash(&pack_id, &pack_version, &reversed);
        prop_assert_ne!(h_normal, h_reversed);
    }

    /// 5. Outcome flip is detectable: changing a single test's outcome
    ///    from Pass to Fail (with any reason) changes the hash.
    #[test]
    fn pack_hash_changes_when_an_outcome_flips_pass_to_fail(
        pack_id in "[a-z-]{1,32}",
        pack_version in "[0-9]{1,3}",
        runs in prop::collection::vec(arb_test_run(), 1..8),
        flip_idx in 0_usize..8,
        fail_reason in ".{0,16}",
    ) {
        prop_assume!(!runs.is_empty());
        let idx = flip_idx % runs.len();
        let mut flipped = runs.clone();
        let original_outcome = flipped[idx].outcome.clone();
        flipped[idx].outcome = TestOutcome::fail(fail_reason.clone());
        // Skip if the flip is a no-op (was already that fail).
        prop_assume!(original_outcome != flipped[idx].outcome);
        let h_orig = pack_hash(&pack_id, &pack_version, &runs);
        let h_flipped = pack_hash(&pack_id, &pack_version, &flipped);
        prop_assert_ne!(h_orig, h_flipped);
    }

    /// 6. Evidence sensitivity: two Pass-with-evidence runs with the
    ///    same test_id/version but different evidence yield different
    ///    hashes. This is what makes bundle proofs inherit member
    ///    identity (the bundle pack emits each member's
    ///    digest:pack_hash as evidence).
    #[test]
    fn pack_hash_changes_with_pass_evidence(
        pack_id in "[a-z-]{1,32}",
        test_id in arb_test_id(),
        evidence_a in ".{1,32}",
        evidence_b in ".{1,32}",
    ) {
        prop_assume!(evidence_a != evidence_b);
        let runs_a = vec![TestRun {
            test_id: test_id.clone(),
            test_version: "1".into(),
            outcome: TestOutcome::pass_with(evidence_a),
        }];
        let runs_b = vec![TestRun {
            test_id,
            test_version: "1".into(),
            outcome: TestOutcome::pass_with(evidence_b),
        }];
        prop_assert_ne!(
            pack_hash(&pack_id, "1", &runs_a),
            pack_hash(&pack_id, "1", &runs_b)
        );
    }

    /// 7. Empty pack runs yield a stable hash. Often an edge case
    ///    in hash functions; we assert it's well-defined.
    #[test]
    fn empty_runs_pack_hash_is_stable(
        pack_id in "[a-z-]{1,32}",
        pack_version in "[0-9]{1,3}",
    ) {
        let runs: Vec<TestRun> = vec![];
        let h1 = pack_hash(&pack_id, &pack_version, &runs);
        let h2 = pack_hash(&pack_id, &pack_version, &runs);
        prop_assert_eq!(h1, h2);
    }

    /// 8. Domain-separation: a Pass with an empty-string evidence is
    ///    NOT equal to a bare Pass. Otherwise an attacker could elide
    ///    evidence and produce the same hash.
    #[test]
    fn empty_evidence_is_distinct_from_no_evidence(
        pack_id in "[a-z-]{1,32}",
    ) {
        let runs_bare = vec![TestRun {
            test_id: "x".into(),
            test_version: "1".into(),
            outcome: TestOutcome::pass(),
        }];
        let runs_empty_evidence = vec![TestRun {
            test_id: "x".into(),
            test_version: "1".into(),
            outcome: TestOutcome::pass_with(""),
        }];
        prop_assert_ne!(
            pack_hash(&pack_id, "1", &runs_bare),
            pack_hash(&pack_id, "1", &runs_empty_evidence)
        );
    }

    /// 9. Fail reasons are domain-separated: two Fail runs with
    ///    different reasons differ. Otherwise an attacker could swap
    ///    a "test failed for reason X" record with "test failed for
    ///    reason Y" without detection.
    #[test]
    fn fail_reasons_are_distinguishing(
        pack_id in "[a-z-]{1,32}",
        reason_a in ".{1,32}",
        reason_b in ".{1,32}",
    ) {
        prop_assume!(reason_a != reason_b);
        let runs_a = vec![TestRun {
            test_id: "x".into(),
            test_version: "1".into(),
            outcome: TestOutcome::fail(reason_a),
        }];
        let runs_b = vec![TestRun {
            test_id: "x".into(),
            test_version: "1".into(),
            outcome: TestOutcome::fail(reason_b),
        }];
        prop_assert_ne!(
            pack_hash(&pack_id, "1", &runs_a),
            pack_hash(&pack_id, "1", &runs_b)
        );
    }
}
