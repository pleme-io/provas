//! provas — typed compliance-test framework.
#![allow(clippy::doc_markdown, clippy::doc_lazy_continuation)]
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
//! same pack version → byte-identical `pack_hash`.
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
//! the `pack_hash` differ from the all-pass canonical.

pub mod runner;
pub mod target;
pub mod tests_bundle;
pub mod tests_helm;
pub mod tests_helm_content;
pub mod tests_helm_rendered;
pub mod tests_oci;

pub use runner::{Citation, ComplianceTest, Pack, PackResult, Runner, TestOutcome, TestRun, pack_hash};
pub use target::{BundleMember, Target};

/// Curated openclaw FedRAMP-High image-pack v1. Targets `Target::OciManifest`.
/// Original 6-test pack — kept for back-compat with deployed listings.
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

/// FedRAMP-High image-pack v2 — extended with NIST 800-53 Rev 5 audit
/// + supply-chain controls. Each new test cites the control it
/// satisfies. Use this for new admissions; v1 stays available for
/// existing listings.
#[must_use]
pub fn fedramp_high_openclaw_image_v2() -> Pack {
    Pack {
        id: "fedramp-high-openclaw-image".into(),
        version: "2".into(),
        tests: vec![
            // CM-2 baseline configuration
            Box::new(tests_oci::OciSchemaVersionIsTwo),
            Box::new(tests_oci::OciHasOfficialMediaType),
            Box::new(tests_oci::OciConfigDigestIsSha256),
            Box::new(tests_oci::OciConfigUsesContentAddress),
            // SI-7 software integrity
            Box::new(tests_oci::OciAllLayersAreSha256Pinned),
            Box::new(tests_oci::OciLayerSizesAreSensible),
            // SC-5 resource bounds
            Box::new(tests_oci::OciManifestSizeUnderFourMib),
            // CM-7 least functionality
            Box::new(tests_oci::OciManifestDeclaresOsAndArchitecture),
            // AU-2 audit events
            Box::new(tests_oci::OciHasCreatedTimestampAnnotation),
            // CM-7 / SR-3 supply chain
            Box::new(tests_oci::OciHasSourceAnnotation),
            Box::new(tests_oci::OciHasRevisionAnnotation),
            // SI-2 flaw remediation
            Box::new(tests_oci::OciHasVersionAnnotation),
            // CM-7 SLSA provenance
            Box::new(tests_oci::OciSlsaProvenanceRefIsNonEmpty),
        ],
    }
}

/// FedRAMP-High openclaw helm-content pack v1 — runs against parsed
/// chart sources (`Chart.yaml`, `values.yaml`, templates). 16 tests
/// covering NIST 800-53 control families CM-2, SI-7, AC-3/6, CA-7,
/// SC-7/13, IA-5, AU-2/12, CP-2, SR-3/4.
///
/// Distinct from `fedramp_high_openclaw_helm_v1` (which targets the
/// helm-as-OCI manifest envelope). Both packs may apply to the same
/// chart artifact and are composed in the bundle proof.
#[must_use]
pub fn fedramp_high_openclaw_helm_content_v1() -> Pack {
    Pack {
        id: "fedramp-high-openclaw-helm-content".into(),
        version: "1".into(),
        tests: vec![
            // CM-2
            Box::new(tests_helm_content::HelmChartApiVersionV2),
            Box::new(tests_helm_content::HelmChartHasNameAndVersion),
            Box::new(tests_helm_content::HelmValuesDeclareFedRampHighOverlay),
            // SI-7
            Box::new(tests_helm_content::HelmValuesNoLatestTags),
            Box::new(tests_helm_content::HelmValuesImagesPinnedToDigest),
            // AC-3 / AC-6
            Box::new(tests_helm_content::HelmValuesRunAsNonRoot),
            // SC-5
            Box::new(tests_helm_content::HelmValuesDeclareResourceLimits),
            // CA-7
            Box::new(tests_helm_content::HelmValuesHasHealthProbes),
            // SC-7
            Box::new(tests_helm_content::HelmValuesHasNetworkPolicy),
            Box::new(tests_helm_content::HelmValuesHasPodDisruptionBudget),
            // IA-5
            Box::new(tests_helm_content::HelmValuesNoPlaintextSecrets),
            // SC-13
            Box::new(tests_helm_content::HelmValuesIngressTlsConfigured),
            // CP-2
            Box::new(tests_helm_content::HelmValuesAtLeastTwoReplicas),
            // AU-12
            Box::new(tests_helm_content::HelmValuesHasMetricsMonitoring),
            // SR-3 / SR-4
            Box::new(tests_helm_content::HelmChartDependenciesPinned),
            // CM-7
            Box::new(tests_helm_content::HelmTemplatesNotEmpty),
        ],
    }
}

/// Curated openclaw FedRAMP-High helm-pack v1. Targets `Target::HelmManifest`.
#[must_use]
pub fn fedramp_high_openclaw_helm_v1() -> Pack {
    Pack {
        id: "fedramp-high-openclaw-helm".into(),
        version: "1".into(),
        tests: vec![
            Box::new(tests_helm::HelmSchemaVersionIsTwo),
            Box::new(tests_helm::HelmConfigMediaTypeIsHelm),
            Box::new(tests_helm::HelmConfigDigestIsSha256),
            Box::new(tests_helm::HelmLayersAreSha256Pinned),
            Box::new(tests_helm::HelmLayersUseHelmMediaTypes),
        ],
    }
}

/// FedRAMP-High openclaw helm-rendered pack v1 — runs against the
/// output of `helm template <chart>` (`Vec<Value>` of Kubernetes
/// resources). Closes V13 from the fleet threat model: catches
/// templates that hide non-compliant config from values.yaml
/// inspection.
///
/// 7 NIST 800-53 Rev 5 controls verified at the rendered-resource
/// level: AC-3 (runAsNonRoot, allowPrivilegeEscalation),
/// AC-6 (privileged, capabilities, readOnlyRootFs), SC-5 (resource
/// limits), SI-7 (image digest pinning).
#[must_use]
pub fn fedramp_high_openclaw_helm_rendered_v1() -> Pack {
    Pack {
        id: "fedramp-high-openclaw-helm-rendered".into(),
        version: "1".into(),
        tests: vec![
            Box::new(tests_helm_rendered::HelmRenderedImagesArePinned),
            Box::new(tests_helm_rendered::HelmRenderedPodsRunAsNonRoot),
            Box::new(tests_helm_rendered::HelmRenderedContainersHaveResourceLimits),
            Box::new(tests_helm_rendered::HelmRenderedNoPrivilegedContainers),
            Box::new(tests_helm_rendered::HelmRenderedContainersDropAllCapabilities),
            Box::new(tests_helm_rendered::HelmRenderedContainersHaveReadOnlyRootFs),
            Box::new(tests_helm_rendered::HelmRenderedNoAllowPrivilegeEscalation),
        ],
    }
}

/// FedRAMP-High openclaw helm-rendered pack **v2** — extends v1 with
/// the full Pod Security Standards Restricted profile + NSA/CISA
/// Kubernetes Hardening Guide additions. v1 stays buildable for
/// existing admissions in cartorio.
///
/// New since v1 (added 2026-05-09 per Phase B):
/// - HelmRenderedNoHostNetwork / -HostPID / -HostIPC (PSS Baseline)
/// - HelmRenderedNoHostPath / -HostPort (PSS Baseline)
/// - HelmRenderedSeccompRuntimeDefault (PSS Restricted, SI-3)
/// - HelmRenderedAddOnlyNetBindService (PSS Restricted, AC-6(9))
/// - HelmRenderedAutomountTokenFalse (CIS 5.1.6, AC-3)
/// - HelmRenderedNoDefaultServiceAccount (CIS 5.1.5, AC-3)
/// - HelmRenderedHasPodDisruptionBudget (CP-2)
/// - HelmRenderedHasNetworkPolicy (SC-7)
#[must_use]
pub fn fedramp_high_openclaw_helm_rendered_v2() -> Pack {
    Pack {
        id: "fedramp-high-openclaw-helm-rendered".into(),
        version: "2".into(),
        tests: vec![
            // v1 carryover (citations refreshed in this pass)
            Box::new(tests_helm_rendered::HelmRenderedImagesArePinned),
            Box::new(tests_helm_rendered::HelmRenderedPodsRunAsNonRoot),
            Box::new(tests_helm_rendered::HelmRenderedContainersHaveResourceLimits),
            Box::new(tests_helm_rendered::HelmRenderedNoPrivilegedContainers),
            Box::new(tests_helm_rendered::HelmRenderedContainersDropAllCapabilities),
            Box::new(tests_helm_rendered::HelmRenderedContainersHaveReadOnlyRootFs),
            Box::new(tests_helm_rendered::HelmRenderedNoAllowPrivilegeEscalation),
            // v2 additions (PSS Restricted)
            Box::new(tests_helm_rendered::HelmRenderedNoHostNetwork),
            Box::new(tests_helm_rendered::HelmRenderedNoHostPID),
            Box::new(tests_helm_rendered::HelmRenderedNoHostIPC),
            Box::new(tests_helm_rendered::HelmRenderedNoHostPath),
            Box::new(tests_helm_rendered::HelmRenderedNoHostPort),
            Box::new(tests_helm_rendered::HelmRenderedSeccompRuntimeDefault),
            Box::new(tests_helm_rendered::HelmRenderedAddOnlyNetBindService),
            Box::new(tests_helm_rendered::HelmRenderedAutomountTokenFalse),
            Box::new(tests_helm_rendered::HelmRenderedNoDefaultServiceAccount),
            Box::new(tests_helm_rendered::HelmRenderedHasPodDisruptionBudget),
            Box::new(tests_helm_rendered::HelmRenderedHasNetworkPolicy),
        ],
    }
}

/// FedRAMP-High openclaw image pack **v3** — extends v2 with OCI
/// Image Spec v1.1-grounded predicates (semantic, not shape-only) +
/// auditor-defensible NIST 800-53 Rev 5 citations. v1/v2 stay
/// buildable so existing cartorio admissions remain verifiable.
///
/// Drops the `OciConfigUsesContentAddress` literal duplicate that v2
/// carried (its `run()` body was identical to
/// `OciConfigDigestIsSha256`).
///
/// New since v2 (added 2026-05-09 per Phase B):
/// - OciNoUppercaseInDigestEncoded (OCI MUST NOT)
/// - OciSourceAnnotationIsValidGitUrl (SR-4 semantic)
/// - OciRevisionAnnotationIsHexSha (SR-4 semantic)
/// - OciCreatedAnnotationIsRfc3339 (AU-3 semantic)
/// - OciLicensesAnnotationIsValidSpdx (SA-22 semantic)
/// - OciNoUnknownOrgOpencontainersImageKeys (CM-2; catches typo)
/// - OciAllLayerMediaTypesAreKnown (CM-2)
/// - OciHasSubjectIfClaimingInToto (SR-4 / OCI v1.1)
/// - OciManifestMediaTypeIsCanonical (CM-2)
/// - OciTitleAnnotationIsNonEmpty (CM-8)
/// - OciVendorAnnotationIsNonEmpty (CM-8)
/// - OciBaseNameAndDigestArePaired (SR-4)
#[must_use]
pub fn fedramp_high_openclaw_image_v3() -> Pack {
    Pack {
        id: "fedramp-high-openclaw-image".into(),
        version: "3".into(),
        tests: vec![
            // v2 carryover — minus OciConfigUsesContentAddress duplicate
            Box::new(tests_oci::OciSchemaVersionIsTwo),
            Box::new(tests_oci::OciHasOfficialMediaType),
            Box::new(tests_oci::OciConfigDigestIsSha256),
            Box::new(tests_oci::OciAllLayersAreSha256Pinned),
            Box::new(tests_oci::OciLayerSizesAreSensible),
            Box::new(tests_oci::OciManifestSizeUnderFourMib),
            Box::new(tests_oci::OciManifestDeclaresOsAndArchitecture),
            Box::new(tests_oci::OciHasCreatedTimestampAnnotation),
            Box::new(tests_oci::OciHasSourceAnnotation),
            Box::new(tests_oci::OciHasRevisionAnnotation),
            Box::new(tests_oci::OciHasVersionAnnotation),
            Box::new(tests_oci::OciSlsaProvenanceRefIsNonEmpty),
            // v3 additions (OCI v1.1 + semantic checks)
            Box::new(tests_oci::OciNoUppercaseInDigestEncoded),
            Box::new(tests_oci::OciSourceAnnotationIsValidGitUrl),
            Box::new(tests_oci::OciRevisionAnnotationIsHexSha),
            Box::new(tests_oci::OciCreatedAnnotationIsRfc3339),
            Box::new(tests_oci::OciLicensesAnnotationIsValidSpdx),
            Box::new(tests_oci::OciNoUnknownOrgOpencontainersImageKeys),
            Box::new(tests_oci::OciAllLayerMediaTypesAreKnown),
            Box::new(tests_oci::OciHasSubjectIfClaimingInToto),
            Box::new(tests_oci::OciManifestMediaTypeIsCanonical),
            Box::new(tests_oci::OciTitleAnnotationIsNonEmpty),
            Box::new(tests_oci::OciVendorAnnotationIsNonEmpty),
            Box::new(tests_oci::OciBaseNameAndDigestArePaired),
        ],
    }
}

/// Curated openclaw FedRAMP-High bundle-pack v1. Targets
/// `Target::Bundle`. Asserts the bundle is composed of at least one
/// oci-image and one helm-chart, members are distinct, and every
/// member carries a non-zero `pack_hash`. Member digests +
/// `pack_hashes` are encoded as evidence on the relevant tests, so
/// the bundle's `pack_hash` differentiates between bundles even when
/// every test passes.
#[must_use]
pub fn fedramp_high_openclaw_bundle_v1() -> Pack {
    Pack {
        id: "fedramp-high-openclaw-bundle".into(),
        version: "1".into(),
        tests: vec![
            Box::new(tests_bundle::BundleHasAtLeastOneOciImageMember),
            Box::new(tests_bundle::BundleHasAtLeastOneHelmChartMember),
            Box::new(tests_bundle::BundleMemberDigestsAreDistinct),
            Box::new(tests_bundle::BundleAllMemberPackHashesNonZero),
        ],
    }
}
