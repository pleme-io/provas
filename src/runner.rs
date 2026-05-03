//! Test trait + Pack + deterministic Runner.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use tameshi::hash::Blake3Hash;

use crate::target::Target;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestOutcome {
    Pass,
    Fail { reason: String },
}

impl TestOutcome {
    #[must_use]
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRun {
    pub test_id: String,
    pub test_version: String,
    pub outcome: TestOutcome,
}

pub trait ComplianceTest: Send + Sync {
    fn id(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn run(&self, target: &Target) -> TestOutcome;
}

pub struct Pack {
    pub id: String,
    pub version: String,
    pub tests: Vec<Box<dyn ComplianceTest>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackResult {
    pub pack_id: String,
    pub pack_version: String,
    pub runs: Vec<TestRun>,
    pub pack_hash: Blake3Hash,
    pub all_passed: bool,
}

pub struct Runner;

impl Runner {
    /// Run every test in the pack against the target, in pack-declared
    /// order. The `pack_hash` is computed deterministically from the
    /// runs.
    #[must_use]
    pub fn run_pack(pack: &Pack, target: &Target) -> PackResult {
        let runs: Vec<TestRun> = pack
            .tests
            .iter()
            .map(|t| TestRun {
                test_id: t.id().to_string(),
                test_version: t.version().to_string(),
                outcome: t.run(target),
            })
            .collect();
        let all_passed = runs.iter().all(|r| r.outcome.is_pass());
        let hash = pack_hash(&pack.id, &pack.version, &runs);
        PackResult {
            pack_id: pack.id.clone(),
            pack_version: pack.version.clone(),
            runs,
            pack_hash: hash,
            all_passed,
        }
    }

    /// Verify that re-running the pack against the target yields the
    /// expected `pack_hash`. Returns `Ok(())` on match, otherwise
    /// `Err(actual_hash)` so the caller can log both sides.
    ///
    /// # Errors
    /// Returns `Err(actual)` if the recomputed hash differs from
    /// `expected`.
    pub fn verify_pack(
        pack: &Pack,
        target: &Target,
        expected: &Blake3Hash,
    ) -> Result<(), Blake3Hash> {
        let result = Self::run_pack(pack, target);
        if &result.pack_hash == expected {
            Ok(())
        } else {
            Err(result.pack_hash)
        }
    }
}

/// Deterministic pack hash. The serialization is intentionally
/// rigid: BLAKE3 over the byte stream
/// `pack_id || \0 || pack_version || \0` followed by per-run
/// `test_id || \0 || test_version || \0 || outcome_tag || \0 [|| reason || \0]`.
///
/// Reordering tests, changing the `pack_id`, or changing any outcome
/// changes the hash. That's the proof property: the same hash means
/// the same pack ran the same tests in the same order against the
/// same target with the same outcomes.
#[must_use]
pub fn pack_hash(pack_id: &str, pack_version: &str, runs: &[TestRun]) -> Blake3Hash {
    let mut h = Hasher::new();
    h.update(b"provas-pack-v1\0");
    h.update(pack_id.as_bytes());
    h.update(b"\0");
    h.update(pack_version.as_bytes());
    h.update(b"\0");
    for r in runs {
        h.update(r.test_id.as_bytes());
        h.update(b"\0");
        h.update(r.test_version.as_bytes());
        h.update(b"\0");
        match &r.outcome {
            TestOutcome::Pass => h.update(b"pass\0"),
            TestOutcome::Fail { reason } => {
                h.update(b"fail\0");
                h.update(reason.as_bytes());
                h.update(b"\0")
            }
        };
    }
    Blake3Hash(*h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysPass(&'static str);
    impl ComplianceTest for AlwaysPass {
        fn id(&self) -> &'static str { self.0 }
        fn version(&self) -> &'static str { "1" }
        fn run(&self, _: &Target) -> TestOutcome { TestOutcome::Pass }
    }
    struct AlwaysFail(&'static str, &'static str);
    impl ComplianceTest for AlwaysFail {
        fn id(&self) -> &'static str { self.0 }
        fn version(&self) -> &'static str { "1" }
        fn run(&self, _: &Target) -> TestOutcome {
            TestOutcome::Fail { reason: self.1.into() }
        }
    }

    fn raw_target() -> Target {
        Target::OciManifest {
            bytes: br#"{"schemaVersion":2}"#.to_vec(),
        }
    }

    fn pack(tests: Vec<Box<dyn ComplianceTest>>) -> Pack {
        Pack {
            id: "test-pack".into(),
            version: "1".into(),
            tests,
        }
    }

    #[test]
    fn empty_pack_yields_stable_hash() {
        let p = pack(vec![]);
        let r1 = Runner::run_pack(&p, &raw_target());
        let r2 = Runner::run_pack(&p, &raw_target());
        assert_eq!(r1.pack_hash, r2.pack_hash);
        assert!(r1.all_passed);
    }

    #[test]
    fn all_pass_pack_is_marked_all_passed() {
        let p = pack(vec![
            Box::new(AlwaysPass("a")),
            Box::new(AlwaysPass("b")),
        ]);
        let r = Runner::run_pack(&p, &raw_target());
        assert!(r.all_passed);
        assert_eq!(r.runs.len(), 2);
    }

    #[test]
    fn any_failure_clears_all_passed_flag() {
        let p = pack(vec![
            Box::new(AlwaysPass("a")),
            Box::new(AlwaysFail("b", "broke")),
        ]);
        let r = Runner::run_pack(&p, &raw_target());
        assert!(!r.all_passed);
    }

    #[test]
    fn pack_hash_changes_on_outcome_change() {
        let p_pass = pack(vec![Box::new(AlwaysPass("x"))]);
        let p_fail = pack(vec![Box::new(AlwaysFail("x", "broke"))]);
        let r1 = Runner::run_pack(&p_pass, &raw_target());
        let r2 = Runner::run_pack(&p_fail, &raw_target());
        assert_ne!(r1.pack_hash, r2.pack_hash);
    }

    #[test]
    fn pack_hash_changes_on_pack_id_change() {
        let runs = vec![TestRun {
            test_id: "x".into(),
            test_version: "1".into(),
            outcome: TestOutcome::Pass,
        }];
        let h1 = pack_hash("a", "1", &runs);
        let h2 = pack_hash("b", "1", &runs);
        assert_ne!(h1, h2);
    }

    #[test]
    fn pack_hash_changes_on_pack_version_change() {
        let runs = vec![TestRun {
            test_id: "x".into(),
            test_version: "1".into(),
            outcome: TestOutcome::Pass,
        }];
        let h1 = pack_hash("a", "1", &runs);
        let h2 = pack_hash("a", "2", &runs);
        assert_ne!(h1, h2);
    }

    #[test]
    fn pack_hash_changes_on_test_order() {
        let runs_ab = vec![
            TestRun { test_id: "a".into(), test_version: "1".into(), outcome: TestOutcome::Pass },
            TestRun { test_id: "b".into(), test_version: "1".into(), outcome: TestOutcome::Pass },
        ];
        let runs_ba = vec![
            TestRun { test_id: "b".into(), test_version: "1".into(), outcome: TestOutcome::Pass },
            TestRun { test_id: "a".into(), test_version: "1".into(), outcome: TestOutcome::Pass },
        ];
        let h1 = pack_hash("p", "1", &runs_ab);
        let h2 = pack_hash("p", "1", &runs_ba);
        assert_ne!(h1, h2, "test order is part of the proof");
    }

    #[test]
    fn verify_pack_succeeds_when_hash_matches() {
        let p = pack(vec![Box::new(AlwaysPass("x"))]);
        let r = Runner::run_pack(&p, &raw_target());
        assert!(Runner::verify_pack(&p, &raw_target(), &r.pack_hash).is_ok());
    }

    #[test]
    fn verify_pack_returns_actual_hash_on_mismatch() {
        let p = pack(vec![Box::new(AlwaysPass("x"))]);
        let bogus = Blake3Hash::digest(b"nope");
        let result = Runner::verify_pack(&p, &raw_target(), &bogus);
        let actual = result.expect_err("must mismatch");
        assert_ne!(actual, bogus);
    }
}
