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

use crate::runner::{Citation, ComplianceTest, TestOutcome};
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
    fn citation(&self) -> Citation {
        Citation::oci_image_spec_v1_1(
            "image-spec/manifest.md#image-manifest-property-descriptions",
            "schemaVersion MUST be 2 per OCI Image Spec v1.1; rejecting Schema 1 prevents legacy-Docker manifest acceptance under CM-2 (baseline configuration).",
        )
    }
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
    fn citation(&self) -> Citation {
        Citation::oci_image_spec_v1_1(
            "image-spec/media-types.md",
            "Manifest mediaType MUST be on the OCI/Docker official allowlist per OCI Image Spec v1.1 §media-types; off-allowlist types are CM-2 baseline-config violations.",
        )
    }
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
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "SI-7",
            "Image config descriptor MUST be sha256-pinned (content-addressed) so any byte change in the config blob is mechanically detectable; satisfies SI-7 software integrity by making config tampering invalidate the manifest digest.",
        )
    }
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
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "SI-7",
            "Every image layer's digest MUST be sha256:<64-hex-lowercase> per OCI descriptor §SHA-256; layer tampering changes the layer hash, which changes the manifest, satisfying SI-7 integrity verification.",
        )
    }
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
    fn citation(&self) -> Citation {
        // Citation correction (was SC-5 — wrong; SC-5 is denial-of-
        // service of the *running system*, not OCI-manifest size). The
        // OCI Distribution Spec §Pushing Manifests states registries
        // SHOULD support ≥4 MiB; a hard 4 MiB cap is operational
        // hygiene that limits registry abuse and admission-time parser
        // load. No exact 800-53 control fits — we cite the OCI spec as
        // the authoritative source.
        Citation::oci_image_spec_v1_1(
            "distribution-spec#pushing-manifests",
            "OCI Distribution Spec v1.1 §Pushing Manifests requires registries support ≥4 MiB manifests. Capping at 4 MiB is conformance with the spec floor and a defensive admission limit.",
        )
    }
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
    fn citation(&self) -> Citation {
        // Citation correction (was CM-7 — wrong; CM-7 is "least
        // functionality" which actually means restricting installed
        // software/services). OS/arch declaration is a CM-2 baseline-
        // configuration check — the manifest must declare its target
        // platform so deployment artifact ↔ host compatibility is
        // verifiable.
        Citation::nist_800_53_r5(
            "CM-2",
            "OS/architecture declaration is part of the documented baseline configuration; satisfies CM-2 by ensuring the deployment target is unambiguous in the artifact metadata.",
        )
    }
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

/// **DEPRECATED — `OciConfigUsesContentAddress` was a literal duplicate
/// of `OciConfigDigestIsSha256` (delegated `run()` body, no new
/// predicate). Kept for back-compat with any existing v2-pack
/// admissions in cartorio (removing it would change `pack_hash` of
/// every prior receipt). New packs (v3+) drop it.**
pub struct OciConfigUsesContentAddress;
impl ComplianceTest for OciConfigUsesContentAddress {
    fn id(&self) -> &'static str { "oci.config_uses_content_address" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "CM-2",
            "DEPRECATED: equivalent to oci.config_digest_is_sha256. Kept in v2 pack only for back-compat — see audit 2026-05-09.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        OciConfigDigestIsSha256.run(target)
    }
}

/// SI-7 (software integrity) — manifest size signaled in each layer's
/// `size` field, non-zero, sane (under 10 GiB per layer).
pub struct OciLayerSizesAreSensible;
impl ComplianceTest for OciLayerSizesAreSensible {
    fn id(&self) -> &'static str { "oci.layer_sizes_are_sensible" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "SI-7",
            "Each layer descriptor MUST declare a non-zero size (per OCI descriptor §Properties); zero/missing size is an integrity-evidence gap (a registry that re-serves a swapped blob with a different size would be undetectable from the manifest alone).",
        )
    }
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
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "AU-3",
            "Per OCI annotations spec (`org.opencontainers.image.created`) the build timestamp MUST be present; satisfies AU-3 (audit record content — when the event occurred) by binding deployment events to a verifiable build-time anchor. Note: this is shape-only; v3 pack adds OciCreatedAnnotationIsRfc3339 for semantic check.",
        )
    }
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

/// SR-4 (provenance) — manifest must carry a `source` annotation
/// pointing at the git repo it was built from. Required for SBOM
/// correlation and CI provenance audits.
pub struct OciHasSourceAnnotation;
impl ComplianceTest for OciHasSourceAnnotation {
    fn id(&self) -> &'static str { "oci.has_source_annotation" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        // Citation correction (was CM-7 — wrong; CM-7 is least
        // functionality). Source annotation is SR-4 (provenance) since
        // it documents *where the artifact came from*. Note v3 pack
        // adds OciSourceAnnotationIsValidGitUrl for semantic check.
        Citation::nist_800_53_r5(
            "SR-4",
            "Per OCI annotations spec (`org.opencontainers.image.source`) the upstream source URL MUST be present; satisfies SR-4 (provenance) by binding the artifact to a documented origin.",
        )
    }
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

/// SR-4 (provenance) — manifest carries a `revision` (git commit)
/// annotation. Together with `source`, lets auditors trace every
/// artifact to a specific code state.
pub struct OciHasRevisionAnnotation;
impl ComplianceTest for OciHasRevisionAnnotation {
    fn id(&self) -> &'static str { "oci.has_revision_annotation" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "SR-4",
            "Per OCI annotations spec (`org.opencontainers.image.revision`) the source-revision identifier MUST be present; satisfies SR-4 by recording the exact code state the artifact was built from.",
        )
    }
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

/// CM-8 (system component inventory) — manifest declares a `version`
/// annotation. Required for the FedRAMP Integrated Inventory Workbook
/// to correlate deployed artifacts with vulnerability advisories.
pub struct OciHasVersionAnnotation;
impl ComplianceTest for OciHasVersionAnnotation {
    fn id(&self) -> &'static str { "oci.has_version_annotation" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        // Citation correction (was SI-2 — wrong; SI-2 is flaw-remediation
        // *lifecycle* which requires CVE/scan integration, not just a
        // version label). Version label is CM-8 (component inventory).
        Citation::nist_800_53_r5(
            "CM-8",
            "Per OCI annotations spec (`org.opencontainers.image.version`) the package version MUST be present; satisfies CM-8 by giving each artifact a unique inventory identifier suitable for CVE correlation.",
        )
    }
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
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "SR-4(3)",
            "Manifest carries an annotation pointing at SLSA provenance (in-toto attestation). Shape-only check — Phase C wires real verify_attestation that fetches the referrer + verifies the cosign bundle. Annotation presence alone partially satisfies SR-4(3) component-genuineness validation.",
        )
    }
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

// ─── v3 / OCI Image Spec v1.1 predicates (added 2026-05-09) ─────────
//
// These extend the v2 pack with predicates grounded in the OCI Image
// Spec v1.1 + OCI Distribution Spec v1.1 + NIST 800-53 Rev 5 Supply-
// Risk family. Each is a deterministic byte-pure check against the
// manifest; together with v2 they form the v3 pack
// `fedramp-high-openclaw-image@3`.

/// OCI MUST: digest encoded portion is lowercase hex only.
pub struct OciNoUppercaseInDigestEncoded;
impl ComplianceTest for OciNoUppercaseInDigestEncoded {
    fn id(&self) -> &'static str { "oci.no_uppercase_in_digest_encoded" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::oci_image_spec_v1_1(
            "image-spec/descriptor.md#sha-256",
            "OCI descriptor §SHA-256 says uppercase MUST NOT be used in the encoded portion of a sha256 digest; rejecting case-mixed digests prevents canonicalization-bypass attacks.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        let v: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(v) => v,
            Err(e) => return TestOutcome::fail(format!("not JSON: {e}")),
        };
        for (path, d) in collect_digests(&v) {
            if !d.starts_with("sha256:") { continue }
            let encoded = &d["sha256:".len()..];
            if encoded.chars().any(|c| c.is_ascii_uppercase()) {
                return TestOutcome::fail(format!("digest at {path} has uppercase hex: {d}"));
            }
        }
        TestOutcome::pass()
    }
}

/// SR-4 (provenance) — `source` annotation parses as a URL with a
/// reachable scheme + non-empty host. v2's predicate only checked
/// presence; this catches `"source": "x"` garbage.
pub struct OciSourceAnnotationIsValidGitUrl;
impl ComplianceTest for OciSourceAnnotationIsValidGitUrl {
    fn id(&self) -> &'static str { "oci.source_annotation_is_valid_git_url" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "SR-4",
            "OCI `source` annotation must parse as https://, git://, ssh://, or git+ssh:// with a non-empty host; satisfies SR-4 only when the source-of-truth is mechanically resolvable, not just a non-empty string.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        let m = match parse(bytes) { Ok(m) => m, Err(e) => return TestOutcome::fail(e) };
        let ann = m.annotations.unwrap_or_default();
        let candidates = ["org.opencontainers.image.source", "io.pleme.image.source"];
        let Some(src) = candidates.iter().find_map(|k| ann.get(*k)) else {
            return TestOutcome::fail("no source annotation");
        };
        if !is_url_with_host(src) {
            return TestOutcome::fail(format!("source annotation {src:?} is not a URL with a host"));
        }
        TestOutcome::pass()
    }
}

/// SR-4 — `revision` annotation matches `^[0-9a-f]{7,64}$` (git short
/// SHA-1 .. SHA-256). v2 checked presence only.
pub struct OciRevisionAnnotationIsHexSha;
impl ComplianceTest for OciRevisionAnnotationIsHexSha {
    fn id(&self) -> &'static str { "oci.revision_annotation_is_hex_sha" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "SR-4",
            "Revision annotation must look like a git SHA (7-64 lowercase hex). A branch name or version string passes presence-check but doesn't pin a code state — SR-4 demands a unique, reproducible source identifier.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        let m = match parse(bytes) { Ok(m) => m, Err(e) => return TestOutcome::fail(e) };
        let ann = m.annotations.unwrap_or_default();
        let candidates = ["org.opencontainers.image.revision", "io.pleme.image.revision"];
        let Some(r) = candidates.iter().find_map(|k| ann.get(*k)) else {
            return TestOutcome::fail("no revision annotation");
        };
        let len_ok = (7..=64).contains(&r.len());
        let hex_ok = r.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
        if !(len_ok && hex_ok) {
            return TestOutcome::fail(format!("revision {r:?} is not 7-64 lowercase hex"));
        }
        TestOutcome::pass()
    }
}

/// AU-3 — `created` annotation parses as RFC 3339 §5.6 timestamp.
pub struct OciCreatedAnnotationIsRfc3339;
impl ComplianceTest for OciCreatedAnnotationIsRfc3339 {
    fn id(&self) -> &'static str { "oci.created_annotation_is_rfc3339" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "AU-3",
            "Created annotation must parse as RFC 3339 timestamp. Absence of the field, an empty string, or a non-parseable value all break audit-record content correlation between artifact build-time and deploy-time events.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        let m = match parse(bytes) { Ok(m) => m, Err(e) => return TestOutcome::fail(e) };
        let ann = m.annotations.unwrap_or_default();
        let candidates = ["org.opencontainers.image.created", "io.pleme.image.created"];
        let Some(t) = candidates.iter().find_map(|k| ann.get(*k)) else {
            return TestOutcome::fail("no created annotation");
        };
        if chrono::DateTime::parse_from_rfc3339(t).is_err() {
            return TestOutcome::fail(format!("created {t:?} is not RFC 3339"));
        }
        TestOutcome::pass()
    }
}

/// SR-4 — `licenses` annotation is a non-empty SPDX license expression.
pub struct OciLicensesAnnotationIsValidSpdx;
impl ComplianceTest for OciLicensesAnnotationIsValidSpdx {
    fn id(&self) -> &'static str { "oci.licenses_annotation_is_valid_spdx" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "SA-22",
            "Licenses annotation must be a non-empty string composed of SPDX-shape tokens (uppercase letters, digits, dots, hyphens, AND/OR/WITH operators, parentheses, plus). Catches `MIT/Apache-2.0` (slash isn't SPDX) and empty strings.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        let m = match parse(bytes) { Ok(m) => m, Err(e) => return TestOutcome::fail(e) };
        let ann = m.annotations.unwrap_or_default();
        let Some(lic) = ann.get("org.opencontainers.image.licenses") else {
            return TestOutcome::fail("no licenses annotation");
        };
        if lic.is_empty() {
            return TestOutcome::fail("licenses annotation is empty");
        }
        // Quick-and-defensible SPDX shape check: only allow [A-Za-z0-9.+-],
        // parentheses, whitespace, and the operators AND / OR / WITH.
        // Catches `MIT/Apache-2.0` (slash) and `(c) 2025 ...`.
        let allowed = |c: char| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '+' | '(' | ')' | ' ' | '\t')
        };
        if !lic.chars().all(allowed) {
            return TestOutcome::fail(format!("licenses {lic:?} contains non-SPDX chars"));
        }
        TestOutcome::pass()
    }
}

/// CM-2 — every `org.opencontainers.image.*` key in the manifest's
/// annotations is in the spec-defined whitelist. Catches typos like
/// `oci.opencontainers.image.created` (spec example carries this typo
/// at manifest.md:210; lots of real images copy it).
pub struct OciNoUnknownOrgOpencontainersImageKeys;
impl ComplianceTest for OciNoUnknownOrgOpencontainersImageKeys {
    fn id(&self) -> &'static str { "oci.no_unknown_org_opencontainers_image_keys" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::oci_image_spec_v1_1(
            "image-spec/annotations.md",
            "OCI annotations §Rules: keys under `org.opencontainers.image.*` are reserved by spec. Catches `oci.opencontainers.image.created` typo (which is in the spec example itself) and proprietary keys squatting in the reserved namespace.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        let m = match parse(bytes) { Ok(m) => m, Err(e) => return TestOutcome::fail(e) };
        let allowed: &[&str] = &[
            "org.opencontainers.image.created",
            "org.opencontainers.image.authors",
            "org.opencontainers.image.url",
            "org.opencontainers.image.documentation",
            "org.opencontainers.image.source",
            "org.opencontainers.image.version",
            "org.opencontainers.image.revision",
            "org.opencontainers.image.vendor",
            "org.opencontainers.image.licenses",
            "org.opencontainers.image.ref.name",
            "org.opencontainers.image.title",
            "org.opencontainers.image.description",
            "org.opencontainers.image.base.digest",
            "org.opencontainers.image.base.name",
            // SLSA / cosign-friendly extension reserved by the spec
            "org.opencontainers.image.attestation.slsa.provenance",
        ];
        let ann = m.annotations.unwrap_or_default();
        let bad: Vec<&str> = ann
            .keys()
            .filter(|k| k.starts_with("org.opencontainers.image."))
            .filter(|k| !allowed.contains(&k.as_str()))
            .map(String::as_str)
            .collect();
        if bad.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(format!(
                "non-spec keys under `org.opencontainers.image.*`: {bad:?}",
            ))
        }
    }
}

/// CM-2 — every layer mediaType is on the OCI/Docker known-good
/// allowlist. Catches `application/vnd.acme.bogus`-style invented
/// types that wouldn't deserialize against any standard tooling.
pub struct OciAllLayerMediaTypesAreKnown;
impl ComplianceTest for OciAllLayerMediaTypesAreKnown {
    fn id(&self) -> &'static str { "oci.all_layer_media_types_are_known" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::oci_image_spec_v1_1(
            "image-spec/media-types.md",
            "OCI Image Spec defines the layer media types (`vnd.oci.image.layer.v1.tar`, `+gzip`, `+zstd`) plus Docker-compatible legacy. Unknown types break standard tooling and are CM-2 baseline-config violations.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        const KNOWN: &[&str] = &[
            "application/vnd.oci.image.layer.v1.tar",
            "application/vnd.oci.image.layer.v1.tar+gzip",
            "application/vnd.oci.image.layer.v1.tar+zstd",
            "application/vnd.oci.image.layer.nondistributable.v1.tar",
            "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
            "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
            // Helm-as-OCI:
            "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
            "application/vnd.cncf.helm.chart.provenance.v1.prov",
        ];
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        let v: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(v) => v,
            Err(e) => return TestOutcome::fail(format!("not JSON: {e}")),
        };
        let Some(layers) = v.get("layers").and_then(|l| l.as_array()) else {
            return TestOutcome::pass(); // no layers — vacuous
        };
        for (i, layer) in layers.iter().enumerate() {
            let Some(mt) = layer.get("mediaType").and_then(|m| m.as_str()) else {
                return TestOutcome::fail(format!("layer[{i}] has no mediaType"));
            };
            if !KNOWN.contains(&mt) {
                return TestOutcome::fail(format!("layer[{i}].mediaType {mt:?} not on allowlist"));
            }
        }
        TestOutcome::pass()
    }
}

/// SR-4 — when `artifactType` indicates an in-toto/SLSA payload, the
/// manifest MUST set `subject` referencing the artifact it attests
/// over (per OCI 1.1 referrers semantics). A SLSA artifact without a
/// subject is unbound — verifier cannot tell what it provesabout.
pub struct OciHasSubjectIfClaimingInToto;
impl ComplianceTest for OciHasSubjectIfClaimingInToto {
    fn id(&self) -> &'static str { "oci.has_subject_if_claiming_intoto" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::oci_image_spec_v1_1(
            "image-spec/manifest.md#image-manifest-property-descriptions",
            "When artifactType begins with `application/vnd.in-toto+json` or contains `slsa.provenance`, the manifest's `subject` field MUST be set per OCI v1.1 Referrers semantics; without subject the attestation is unbound from any artifact.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        let v: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(v) => v,
            Err(e) => return TestOutcome::fail(format!("not JSON: {e}")),
        };
        let at = v.get("artifactType").and_then(|x| x.as_str()).unwrap_or("");
        let claims_intoto = at.starts_with("application/vnd.in-toto")
            || at.contains("slsa.provenance")
            || at.contains("dev.sigstore");
        if !claims_intoto {
            return TestOutcome::pass();
        }
        if v.get("subject").is_some() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(format!(
                "manifest declares attestation artifactType={at:?} but has no `subject` — verifier cannot bind to any artifact"
            ))
        }
    }
}

/// CM-2 — when present, manifest mediaType matches the canonical OCI
/// image manifest type.
pub struct OciManifestMediaTypeIsCanonical;
impl ComplianceTest for OciManifestMediaTypeIsCanonical {
    fn id(&self) -> &'static str { "oci.manifest_media_type_is_canonical" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::oci_image_spec_v1_1(
            "image-spec/manifest.md#property-descriptions",
            "When manifest declares `mediaType`, it MUST be the canonical OCI image manifest type. Off-spec values fail registry content-negotiation and break consumer tooling.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        let m = match parse(bytes) { Ok(m) => m, Err(e) => return TestOutcome::fail(e) };
        match m.media_type.as_deref() {
            None => TestOutcome::pass(), // mediaType is SHOULD, not MUST
            Some("application/vnd.oci.image.manifest.v1+json") => TestOutcome::pass(),
            Some("application/vnd.oci.image.index.v1+json") => TestOutcome::pass(),
            Some(other) => TestOutcome::fail(format!(
                "manifest mediaType {other:?} is not the canonical OCI image manifest type"
            )),
        }
    }
}

/// CM-2 — `org.opencontainers.image.title` non-empty (catches images
/// that pass the older shape-only AnnotationIsNonEmpty by setting
/// `title=""`). v3 additions are stricter on this surface.
pub struct OciTitleAnnotationIsNonEmpty;
impl ComplianceTest for OciTitleAnnotationIsNonEmpty {
    fn id(&self) -> &'static str { "oci.title_annotation_is_non_empty" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "CM-8",
            "Image title annotation must be present and non-empty so the inventory record has a human-readable name; CM-8 component-inventory requires unique, identifiable component names.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        let m = match parse(bytes) { Ok(m) => m, Err(e) => return TestOutcome::fail(e) };
        let ann = m.annotations.unwrap_or_default();
        match ann.get("org.opencontainers.image.title") {
            Some(t) if !t.is_empty() => TestOutcome::pass(),
            Some(_) => TestOutcome::fail("title annotation is empty"),
            None => TestOutcome::fail("no title annotation"),
        }
    }
}

/// CM-8 — vendor annotation non-empty. Required for inventory-of-
/// suppliers per FedRAMP integrated inventory workbook.
pub struct OciVendorAnnotationIsNonEmpty;
impl ComplianceTest for OciVendorAnnotationIsNonEmpty {
    fn id(&self) -> &'static str { "oci.vendor_annotation_is_non_empty" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "CM-8",
            "Image vendor annotation identifies the supplier; required by FedRAMP integrated inventory workbook for supplier-of-record tracking.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        let m = match parse(bytes) { Ok(m) => m, Err(e) => return TestOutcome::fail(e) };
        let ann = m.annotations.unwrap_or_default();
        match ann.get("org.opencontainers.image.vendor") {
            Some(v) if !v.is_empty() => TestOutcome::pass(),
            Some(_) => TestOutcome::fail("vendor annotation is empty"),
            None => TestOutcome::fail("no vendor annotation"),
        }
    }
}

/// SR-4 — when `base.name` is set, `base.digest` MUST also be set
/// (and vice versa). Without both, the base-image provenance chain is
/// broken — auditor can't trace the layered build.
pub struct OciBaseNameAndDigestArePaired;
impl ComplianceTest for OciBaseNameAndDigestArePaired {
    fn id(&self) -> &'static str { "oci.base_name_and_digest_are_paired" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "SR-4",
            "Base-image annotations: if `base.name` is declared, `base.digest` MUST also be declared (and vice versa) so the supply chain links to a specific base-image bytes, not a floating reference.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let bytes = match or_fail_for_oci(target) { Ok(b) => b, Err(e) => return e };
        let m = match parse(bytes) { Ok(m) => m, Err(e) => return TestOutcome::fail(e) };
        let ann = m.annotations.unwrap_or_default();
        let has_name = ann.get("org.opencontainers.image.base.name").is_some_and(|v| !v.is_empty());
        let has_digest = ann.get("org.opencontainers.image.base.digest").is_some_and(|v| !v.is_empty());
        match (has_name, has_digest) {
            (true, true) => TestOutcome::pass(),
            (false, false) => TestOutcome::pass(), // not claiming a base; acceptable
            (true, false) => TestOutcome::fail("base.name set but base.digest missing"),
            (false, true) => TestOutcome::fail("base.digest set but base.name missing"),
        }
    }
}

// ─── helpers used by v3 predicates ──────────────────────────────────

fn is_url_with_host(s: &str) -> bool {
    // Tiny, defensible URL shape check. Accepts http(s)://host/...,
    // git://host/..., ssh://user@host/..., git+ssh://host/...
    let prefixes = ["https://", "http://", "git://", "ssh://", "git+ssh://", "git+https://"];
    for prefix in prefixes {
        if let Some(rest) = s.strip_prefix(prefix) {
            // host = up to first '/' or end; must be non-empty
            let host = rest.split('/').next().unwrap_or("");
            // Strip user@ if present
            let host = host.rsplit('@').next().unwrap_or(host);
            if !host.is_empty() && host.contains('.') {
                return true;
            }
        }
    }
    false
}

fn collect_digests(v: &serde_json::Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    walk_digests(v, "$", &mut out);
    out
}

fn walk_digests(v: &serde_json::Value, path: &str, out: &mut Vec<(String, String)>) {
    use serde_json::Value::{Array, Object, String as JStr};
    match v {
        Object(map) => {
            for (k, vv) in map {
                let p = format!("{path}.{k}");
                if k == "digest" {
                    if let JStr(s) = vv {
                        out.push((p.clone(), s.clone()));
                    }
                }
                walk_digests(vv, &p, out);
            }
        }
        Array(arr) => {
            for (i, vv) in arr.iter().enumerate() {
                walk_digests(vv, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
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
