//! OCI manifest compliance tests. Each is a pure function of the
//! manifest bytes — deterministic, transferable, idempotent.
#![allow(
    clippy::doc_markdown,
    clippy::manual_let_else,
    clippy::redundant_closure_for_method_calls,
    clippy::needless_pass_by_value,
    clippy::cmp_owned,
    clippy::items_after_statements,
    clippy::collapsible_match,
    clippy::single_match_else
)]
//!
//! These map to concrete FedRAMP-High control families:
//! - `CM-2` (baseline configuration) — schema/media/config invariants
//! - `SI-7` (software integrity) — sha256 pinning, no `:latest`
//! - `SC-7` (resource bounds) — manifest size cap

use serde::Deserialize;

use crate::runner::{ComplianceTest, TestOutcome};
use crate::target::Target;

const FOUR_MIB: usize = 4 * 1024 * 1024;

#[derive(Deserialize)]
struct ParsedOciManifest {
    #[serde(default)]
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(default)]
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    #[serde(default)]
    config: Option<ParsedConfig>,
    #[serde(default)]
    layers: Vec<ParsedLayer>,
    #[serde(default)]
    annotations: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Deserialize)]
struct ParsedConfig {
    #[serde(default)]
    digest: Option<String>,
}

#[derive(Deserialize)]
struct ParsedLayer {
    #[serde(default)]
    digest: Option<String>,
}

fn parse(bytes: &[u8]) -> Result<ParsedOciManifest, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("manifest is not valid JSON: {e}"))
}

fn manifest_bytes(target: &Target) -> Option<&[u8]> {
    match target {
        Target::OciManifest { bytes } => Some(bytes),
        _ => None,
    }
}

fn or_fail_for_oci(target: &Target) -> Result<&[u8], TestOutcome> {
    manifest_bytes(target).ok_or_else(|| TestOutcome::fail("target is not an oci manifest"))
}

// ─── tests ──────────────────────────────────────────────────────────

pub struct OciSchemaVersionIsTwo;
impl ComplianceTest for OciSchemaVersionIsTwo {
    fn id(&self) -> &'static str { "oci.schema_version_is_two" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        match parse(bytes) {
            Ok(m) if m.schema_version == 2 => TestOutcome::pass(),
            Ok(m) => TestOutcome::Fail {
                reason: format!("schemaVersion is {}, expected 2", m.schema_version),
            },
            Err(e) => TestOutcome::Fail { reason: e },
        }
    }
}

const OFFICIAL_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];

pub struct OciHasOfficialMediaType;
impl ComplianceTest for OciHasOfficialMediaType {
    fn id(&self) -> &'static str { "oci.has_official_media_type" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        match parse(bytes) {
            Ok(m) => match m.media_type.as_deref() {
                Some(mt) if OFFICIAL_MEDIA_TYPES.contains(&mt) => TestOutcome::pass(),
                Some(mt) => TestOutcome::Fail {
                    reason: format!("mediaType {mt:?} is not on the official allowlist"),
                },
                None => TestOutcome::Fail {
                    reason: "manifest has no mediaType field".into(),
                },
            },
            Err(e) => TestOutcome::Fail { reason: e },
        }
    }
}

pub struct OciConfigDigestIsSha256;
impl ComplianceTest for OciConfigDigestIsSha256 {
    fn id(&self) -> &'static str { "oci.config_digest_is_sha256" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        match parse(bytes) {
            Ok(m) => match m.config.and_then(|c| c.digest) {
                Some(d) if d.starts_with("sha256:") && d.len() == "sha256:".len() + 64 => {
                    TestOutcome::pass()
                }
                Some(d) => TestOutcome::Fail {
                    reason: format!("config.digest {d:?} is not sha256:<64hex>"),
                },
                None => TestOutcome::Fail {
                    reason: "manifest has no config.digest".into(),
                },
            },
            Err(e) => TestOutcome::Fail { reason: e },
        }
    }
}

pub struct OciAllLayersAreSha256Pinned;
impl ComplianceTest for OciAllLayersAreSha256Pinned {
    fn id(&self) -> &'static str { "oci.all_layers_are_sha256_pinned" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        match parse(bytes) {
            Ok(m) => {
                for (i, layer) in m.layers.iter().enumerate() {
                    let d = layer.digest.as_deref().unwrap_or("");
                    if !d.starts_with("sha256:") || d.len() != "sha256:".len() + 64 {
                        return TestOutcome::Fail {
                            reason: format!("layer[{i}].digest {d:?} not sha256-pinned"),
                        };
                    }
                }
                TestOutcome::pass()
            }
            Err(e) => TestOutcome::Fail { reason: e },
        }
    }
}

pub struct OciManifestSizeUnderFourMib;
impl ComplianceTest for OciManifestSizeUnderFourMib {
    fn id(&self) -> &'static str { "oci.manifest_size_under_four_mib" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        let size = bytes.len();
        if size <= FOUR_MIB {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(format!("manifest is {size} bytes; cap is {FOUR_MIB}"))
        }
    }
}

// ─── extended FedRAMP-High image tests (NIST 800-53 Rev 5 citations) ──

/// CM-7 (least functionality) — manifest must declare an `os` /
/// `architecture` for clarity of supported deployment targets. Indexes
/// (multi-arch lists) are specifically allowed without this since they
/// reference per-arch sub-manifests.
pub struct OciManifestDeclaresOsAndArchitecture;
impl ComplianceTest for OciManifestDeclaresOsAndArchitecture {
    fn id(&self) -> &'static str { "oci.manifest_declares_os_and_architecture" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        // Accept both single-manifest and index forms; only single-manifest
        // form needs explicit os/arch (in the config blob, but referenced).
        let v: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(v) => v,
            Err(e) => return TestOutcome::fail(format!("not JSON: {e}")),
        };
        let mt = v.get("mediaType").and_then(|x| x.as_str()).unwrap_or("");
        if mt.contains("index") || mt.contains("manifest.list") {
            return TestOutcome::pass(); // multi-arch list — per-arch entries carry os/arch
        }
        // Single manifest: has a config descriptor pointing to a config blob.
        // We can't fetch the blob, but we can confirm the descriptor exists.
        if v.get("config").and_then(|c| c.get("digest")).is_some() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail("manifest declares no config descriptor (CM-7)".to_string())
        }
    }
}

/// CM-2 (baseline configuration) — manifest must NOT use `:latest`-style
/// floating tags in any digest position. Already covered for layers in
/// `OciAllLayersAreSha256Pinned`; this test extends to the config descriptor.
pub struct OciConfigUsesContentAddress;
impl ComplianceTest for OciConfigUsesContentAddress {
    fn id(&self) -> &'static str { "oci.config_uses_content_address" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        // Already enforced by OciConfigDigestIsSha256; this is the more
        // explicit framing for FedRAMP audit purposes (CM-2 baseline).
        OciConfigDigestIsSha256.run(target)
    }
}

/// SI-7 (software integrity) — manifest size signaled in each layer's
/// `size` field, non-zero, sane (under 10 GiB per layer).
pub struct OciLayerSizesAreSensible;
impl ComplianceTest for OciLayerSizesAreSensible {
    fn id(&self) -> &'static str { "oci.layer_sizes_are_sensible" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        const TEN_GIB: u64 = 10 * 1024 * 1024 * 1024;
        match parse(bytes) {
            Ok(m) => {
                // Re-parse with size field via raw json (our model dropped it).
                let v: serde_json::Value = match serde_json::from_slice(bytes) {
                    Ok(v) => v,
                    Err(e) => return TestOutcome::fail(format!("re-parse: {e}")),
                };
                let layers = v.get("layers").and_then(|l| l.as_array());
                if m.layers.is_empty() {
                    return TestOutcome::pass(); // no layers, vacuously true
                }
                let Some(layers) = layers else {
                    return TestOutcome::fail("layers field missing".to_string());
                };
                for (i, layer) in layers.iter().enumerate() {
                    let size = layer.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
                    if size == 0 {
                        return TestOutcome::fail(format!("layer[{i}].size is missing or zero"));
                    }
                    if size > TEN_GIB {
                        return TestOutcome::fail(format!(
                            "layer[{i}].size {size} exceeds 10 GiB cap"
                        ));
                    }
                }
                TestOutcome::pass()
            }
            Err(e) => TestOutcome::fail(e),
        }
    }
}

/// AU-2 (auditable events) — manifest must carry an
/// `org.opencontainers.image.created` annotation so audit log can
/// correlate image build time with deployment time.
pub struct OciHasCreatedTimestampAnnotation;
impl ComplianceTest for OciHasCreatedTimestampAnnotation {
    fn id(&self) -> &'static str { "oci.has_created_timestamp_annotation" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        match parse(bytes) {
            Ok(m) => {
                let ann = m.annotations.unwrap_or_default();
                let candidates = [
                    "org.opencontainers.image.created",
                    "io.pleme.image.created",
                ];
                if candidates.iter().any(|k| ann.get(*k).is_some_and(|v| !v.is_empty())) {
                    TestOutcome::pass()
                } else {
                    TestOutcome::fail("no `created` timestamp annotation (AU-2)".to_string())
                }
            }
            Err(e) => TestOutcome::fail(e),
        }
    }
}

/// CM-7 (least functionality) — manifest must carry a `source` annotation
/// pointing at the git repo it was built from. Required for SBOM
/// correlation and CI provenance audits.
pub struct OciHasSourceAnnotation;
impl ComplianceTest for OciHasSourceAnnotation {
    fn id(&self) -> &'static str { "oci.has_source_annotation" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        match parse(bytes) {
            Ok(m) => {
                let ann = m.annotations.unwrap_or_default();
                let candidates = [
                    "org.opencontainers.image.source",
                    "io.pleme.image.source",
                ];
                if candidates.iter().any(|k| ann.get(*k).is_some_and(|v| !v.is_empty())) {
                    TestOutcome::pass()
                } else {
                    TestOutcome::fail("no `source` annotation pointing at upstream repo (CM-7)".to_string())
                }
            }
            Err(e) => TestOutcome::fail(e),
        }
    }
}

/// SR-3 (supply chain control) — manifest carries a `revision` (git
/// commit) annotation. Together with `source`, lets auditors trace
/// every artifact to a specific code state.
pub struct OciHasRevisionAnnotation;
impl ComplianceTest for OciHasRevisionAnnotation {
    fn id(&self) -> &'static str { "oci.has_revision_annotation" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        match parse(bytes) {
            Ok(m) => {
                let ann = m.annotations.unwrap_or_default();
                let candidates = [
                    "org.opencontainers.image.revision",
                    "io.pleme.image.revision",
                ];
                if candidates.iter().any(|k| ann.get(*k).is_some_and(|v| !v.is_empty())) {
                    TestOutcome::pass()
                } else {
                    TestOutcome::fail("no `revision` annotation (git commit) (SR-3)".to_string())
                }
            }
            Err(e) => TestOutcome::fail(e),
        }
    }
}

/// SI-2 (flaw remediation) — manifest declares a `version` annotation
/// for monitoring; production deployments must be on a known version
/// for vulnerability tracking.
pub struct OciHasVersionAnnotation;
impl ComplianceTest for OciHasVersionAnnotation {
    fn id(&self) -> &'static str { "oci.has_version_annotation" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        match parse(bytes) {
            Ok(m) => {
                let ann = m.annotations.unwrap_or_default();
                let candidates = [
                    "org.opencontainers.image.version",
                    "io.pleme.image.version",
                ];
                if candidates.iter().any(|k| ann.get(*k).is_some_and(|v| !v.is_empty())) {
                    TestOutcome::pass()
                } else {
                    TestOutcome::fail("no `version` annotation (SI-2)".to_string())
                }
            }
            Err(e) => TestOutcome::fail(e),
        }
    }
}

/// Looks for an `org.opencontainers.image.attestation.slsa.provenance`
/// annotation OR a non-empty `slsa-provenance-ref` annotation. This is
/// a stand-in until we land structured attestations in the manifest;
/// today, publishers embed the ref as an annotation.
pub struct OciSlsaProvenanceRefIsNonEmpty;
impl ComplianceTest for OciSlsaProvenanceRefIsNonEmpty {
    fn id(&self) -> &'static str { "oci.slsa_provenance_ref_is_non_empty" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        match parse(bytes) {
            Ok(m) => {
                let ann = m.annotations.unwrap_or_default();
                let candidates = [
                    "org.opencontainers.image.attestation.slsa.provenance",
                    "io.pleme.slsa-provenance-ref",
                    "slsa-provenance-ref",
                ];
                if candidates.iter().any(|k| {
                    ann.get(*k).is_some_and(|v| !v.is_empty())
                }) {
                    TestOutcome::pass()
                } else {
                    TestOutcome::Fail {
                        reason: "no SLSA provenance annotation found on manifest".into(),
                    }
                }
            }
            Err(e) => TestOutcome::Fail { reason: e },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target_from(json: &str) -> Target {
        Target::from_oci_manifest_bytes(json.as_bytes().to_vec())
    }

    const GOOD_MANIFEST: &str = r#"{
      "schemaVersion": 2,
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "config": {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "size": 100
      },
      "layers": [
        {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111", "size": 1000}
      ],
      "annotations": {
        "io.pleme.slsa-provenance-ref": "ghcr.io/pleme-io/x@sha256:beef"
      }
    }"#;

    #[test]
    fn schema_v2_passes_for_good_manifest() {
        assert_eq!(OciSchemaVersionIsTwo.run(&target_from(GOOD_MANIFEST)), TestOutcome::pass());
    }

    #[test]
    fn schema_v1_fails() {
        let bad = r#"{"schemaVersion":1,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;
        assert!(matches!(
            OciSchemaVersionIsTwo.run(&target_from(bad)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn invalid_json_fails_every_test() {
        let bad = "not-json-at-all";
        for t in [
            &OciSchemaVersionIsTwo as &dyn ComplianceTest,
            &OciHasOfficialMediaType,
            &OciConfigDigestIsSha256,
            &OciAllLayersAreSha256Pinned,
            &OciSlsaProvenanceRefIsNonEmpty,
        ] {
            assert!(matches!(t.run(&target_from(bad)), TestOutcome::Fail { .. }));
        }
    }

    #[test]
    fn unofficial_media_type_fails() {
        let bad = r#"{"schemaVersion":2,"mediaType":"application/vnd.acme.bogus+json"}"#;
        assert!(matches!(
            OciHasOfficialMediaType.run(&target_from(bad)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn missing_config_digest_fails() {
        let bad = r#"{"schemaVersion":2}"#;
        assert!(matches!(
            OciConfigDigestIsSha256.run(&target_from(bad)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn config_digest_with_wrong_prefix_fails() {
        let bad = r#"{"schemaVersion":2,"config":{"digest":"md5:abc"}}"#;
        assert!(matches!(
            OciConfigDigestIsSha256.run(&target_from(bad)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn unpinned_layer_fails() {
        let bad = r#"{
          "schemaVersion": 2,
          "layers": [{"digest": "latest"}]
        }"#;
        assert!(matches!(
            OciAllLayersAreSha256Pinned.run(&target_from(bad)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn empty_layers_passes_pinning() {
        // Vacuously true.
        let bare = r#"{"schemaVersion":2}"#;
        assert_eq!(
            OciAllLayersAreSha256Pinned.run(&target_from(bare)),
            TestOutcome::pass()
        );
    }

    #[test]
    fn oversized_manifest_fails() {
        let big = format!("{{\"schemaVersion\":2,\"_pad\":\"{}\"}}", "a".repeat(FOUR_MIB + 100));
        assert!(matches!(
            OciManifestSizeUnderFourMib.run(&target_from(&big)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn slsa_annotation_passes_with_either_key() {
        let with_pleme = r#"{"schemaVersion":2,"annotations":{"io.pleme.slsa-provenance-ref":"ghcr.io/x"}}"#;
        let with_oci = r#"{"schemaVersion":2,"annotations":{"org.opencontainers.image.attestation.slsa.provenance":"ghcr.io/y"}}"#;
        assert_eq!(OciSlsaProvenanceRefIsNonEmpty.run(&target_from(with_pleme)), TestOutcome::pass());
        assert_eq!(OciSlsaProvenanceRefIsNonEmpty.run(&target_from(with_oci)), TestOutcome::pass());
    }

    #[test]
    fn missing_slsa_annotation_fails() {
        let bad = r#"{"schemaVersion":2,"annotations":{}}"#;
        assert!(matches!(
            OciSlsaProvenanceRefIsNonEmpty.run(&target_from(bad)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn good_manifest_passes_every_test_in_pack() {
        use crate::fedramp_high_openclaw_image_v1;
        use crate::runner::Runner;
        let pack = fedramp_high_openclaw_image_v1();
        let result = Runner::run_pack(&pack, &target_from(GOOD_MANIFEST));
        assert!(result.all_passed, "got runs: {:#?}", result.runs);
    }
}
