//! provas — typed compliance-test framework.
//!
//! A `Pack` is a pinned, ordered list of `ComplianceTest`s. Running a
//! pack against a `Target` yields a `PackResult` whose `pack_hash` is
//! `blake3(canonical_serialize(test_id || version || outcome))` over
//! the runs in pack-declared order.
//!
//! That hash is what cartorio stores as
//! `ComplianceAttestation.result_hash`. Anyone with the same pack
//! definition + same target can re-run and verify the same hash falls
//! out — no trust required, the proof is transferable by construction.
//!
//! Determinism is non-negotiable: tests must be pure functions of the
//! target. No `now()`, no PRNG, no env, no network. Same target +
//! same pack version → byte-identical pack_hash.
//!
//! # Provable statement shape
//!
//! "Artifact A is compliant under pack P" iff:
//!
//! - `A.attestation.compliance.profile == P.id @ P.version`
//! - `A.attestation.compliance.result_hash == Runner::run_pack(P, A.target).pack_hash`
//! - every test in the pack yielded `Pass`
//!
//! The first two equalities are checked by `verify_pack`; the third is
//! also checked by `verify_pack` because a `Fail` in any test makes
//! the pack_hash differ from the all-pass canonical.

pub mod runner;
pub mod target;
pub mod tests_oci;

pub use runner::{ComplianceTest, Pack, PackResult, Runner, TestOutcome, TestRun, pack_hash};
pub use target::Target;

/// Curated openclaw FedRAMP-High image-pack v1.
#[must_use]
pub fn fedramp_high_openclaw_image_v1() -> Pack {
    Pack {
        id: "fedramp-high-openclaw-image".into(),
        version: "1".into(),
        tests: vec![
            Box::new(tests_oci::OciSchemaVersionIsTwo),
            Box::new(tests_oci::OciHasOfficialMediaType),
            Box::new(tests_oci::OciConfigDigestIsSha256),
            Box::new(tests_oci::OciAllLayersAreSha256Pinned),
            Box::new(tests_oci::OciManifestSizeUnderFourMib),
            Box::new(tests_oci::OciSlsaProvenanceRefIsNonEmpty),
        ],
    }
}
