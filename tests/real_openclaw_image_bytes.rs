//! Real-bytes integration test for the OCI image v3 pack.
//!
//! Runs `fedramp-high-openclaw-image@3` against an **actual ghcr
//! manifest** captured from `ghcr.io/pleme-io/openclaw-publisher-pki`
//! (digest `sha256:f6505fd3…`). The fixture is the verbatim manifest
//! body served by ghcr; re-hashing the bytes reproduces the original
//! digest.
//!
//! Phase B closes the cartorio audit's #1 critical gap: **no provas
//! test ever ran against bytes pulled from a real registry**. This
//! test plants the real-bytes path in CI so future regressions are
//! visible.
//!
//! Honest about what's currently broken: the captured 2026-05-09
//! manifest has NO `org.opencontainers.image.*` annotations (verified
//! via `head` on the fixture). v3's annotation-semantics tests will
//! FAIL — that's the signal Phase E (chart hardening + image
//! republish with annotations) must address.

use provas::{Runner, Target, fedramp_high_openclaw_image_v3};

const FIXTURE: &[u8] = include_bytes!(
    "fixtures/openclaw-publisher-pki-f6505fd.json"
);

const FIXTURE_DIGEST_HEX: &str =
    "f6505fd3d15c6b5305edbda14650c0bfc12094197159b2ee4318349577eb7f8a";

/// Sanity: the captured fixture's bytes really do hash to the
/// digest the test name claims (no fixture rot).
#[test]
fn fixture_byte_hash_matches_claimed_digest() {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(FIXTURE);
    let actual = hex::encode(h.finalize());
    assert_eq!(
        actual, FIXTURE_DIGEST_HEX,
        "fixture has rotted; re-fetch from ghcr"
    );
}

/// Run the v3 pack against the real bytes. We assert the deterministic
/// outcome split — these are the predicates the live openclaw image
/// satisfies today, vs the ones it doesn't. When Phase E republishes
/// openclaw with proper annotations, this test's expected set flips
/// and the change is visible in the diff.
#[test]
fn real_openclaw_image_v3_pack_outcome_is_deterministic() {
    let pack = fedramp_high_openclaw_image_v3();
    let target = Target::from_oci_manifest_bytes(FIXTURE.to_vec());
    let result = Runner::run_pack(&pack, &target);

    // Tests the real image PASSES today (structural OCI invariants):
    let passes_today = [
        "oci.schema_version_is_two",                      // schemaVersion=2
        "oci.has_official_media_type",                    // docker manifest v2
        "oci.config_digest_is_sha256",                    // sha256-pinned
        "oci.all_layers_are_sha256_pinned",               // sha256-pinned
        "oci.layer_sizes_are_sensible",                   // non-zero, sane
        "oci.manifest_size_under_four_mib",               // 3 KiB
        "oci.manifest_declares_os_and_architecture",      // has config descriptor
        "oci.no_uppercase_in_digest_encoded",             // lowercase hex
        "oci.no_unknown_org_opencontainers_image_keys",   // no annotations at all
        "oci.all_layer_media_types_are_known",            // docker tar.gzip
        "oci.has_subject_if_claiming_intoto",             // not claiming intoto
        "oci.base_name_and_digest_are_paired",            // neither annotation present
    ];
    // Tests the real image FAILS today (missing annotations):
    let fails_today = [
        "oci.has_created_timestamp_annotation",
        "oci.has_source_annotation",
        "oci.has_revision_annotation",
        "oci.has_version_annotation",
        "oci.slsa_provenance_ref_is_non_empty",
        "oci.source_annotation_is_valid_git_url",
        "oci.revision_annotation_is_hex_sha",
        "oci.created_annotation_is_rfc3339",
        "oci.licenses_annotation_is_valid_spdx",
        "oci.title_annotation_is_non_empty",
        "oci.vendor_annotation_is_non_empty",
        // Real openclaw is published with Docker mediaType (built via
        // docker tooling, not OCI tooling). Phase E will republish via
        // Nix's `dockerTools.streamLayeredImage` with explicit OCI
        // manifest mediaType — at which point this flips to passes_today.
        "oci.manifest_media_type_is_canonical",
    ];

    let outcome_for = |id: &str| {
        result
            .runs
            .iter()
            .find(|r| r.test_id == id)
            .unwrap_or_else(|| panic!("pack v3 missing test {id}"))
    };

    for id in passes_today {
        let r = outcome_for(id);
        assert!(
            r.outcome.is_pass(),
            "expected real openclaw image to pass `{id}`, got: {:#?}",
            r.outcome,
        );
    }
    for id in fails_today {
        let r = outcome_for(id);
        assert!(
            !r.outcome.is_pass(),
            "expected real openclaw image to FAIL `{id}` (annotation absent), but it passed",
        );
    }

    // pack_hash is deterministic against these bytes — committing it
    // here means any future drift (in pack code, in fixture, in
    // hashing) is caught by this test.
    let actual_hash = result.pack_hash.to_hex();
    eprintln!("real openclaw v3 pack_hash against ghcr digest sha256:{FIXTURE_DIGEST_HEX} = {actual_hash}");
    // Don't pin the hash literal here yet — Phase B is the first run.
    // Phase C wires real publish flow and at that point we pin the hash
    // alongside the canonical attestation.
    assert!(!actual_hash.is_empty());
}
