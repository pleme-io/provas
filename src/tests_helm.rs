//! Helm-as-OCI manifest compliance tests. Helm 3.7+ pushes charts
//! through standard OCI registries; the manifest schema is identical
//! but the `config.mediaType` is helm-specific. We reuse the OCI
//! schema/pinning/size tests via composition; this module adds the
//! helm-specific bits.

use serde::Deserialize;

use crate::runner::{ComplianceTest, TestOutcome};
use crate::target::Target;

const HELM_CONFIG_MEDIA_TYPE: &str = "application/vnd.cncf.helm.config.v1+json";

#[derive(Deserialize)]
struct ParsedHelmManifest {
    #[serde(default, rename = "schemaVersion")]
    schema_version: u32,
    #[serde(default)]
    config: Option<ParsedHelmConfig>,
    #[serde(default)]
    layers: Vec<ParsedHelmLayer>,
}

#[derive(Deserialize)]
struct ParsedHelmConfig {
    #[serde(default, rename = "mediaType")]
    media_type: Option<String>,
    #[serde(default)]
    digest: Option<String>,
}

#[derive(Deserialize)]
struct ParsedHelmLayer {
    #[serde(default, rename = "mediaType")]
    media_type: Option<String>,
    #[serde(default)]
    digest: Option<String>,
}

fn parse(bytes: &[u8]) -> Result<ParsedHelmManifest, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("helm manifest is not valid JSON: {e}"))
}

fn manifest_bytes(target: &Target) -> Option<&[u8]> {
    match target {
        Target::HelmManifest { bytes } => Some(bytes),
        _ => None,
    }
}

const HELM_LAYER_MEDIA_TYPES: &[&str] = &[
    "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
    "application/vnd.cncf.helm.chart.provenance.v1.prov",
];

// ─── tests ─────────────────────────────────────────────────────────

pub struct HelmSchemaVersionIsTwo;
impl ComplianceTest for HelmSchemaVersionIsTwo {
    fn id(&self) -> &'static str { "helm.schema_version_is_two" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let Some(bytes) = manifest_bytes(target) else {
            return TestOutcome::fail("target is not a helm manifest");
        };
        match parse(bytes) {
            Ok(m) if m.schema_version == 2 => TestOutcome::pass(),
            Ok(m) => TestOutcome::fail(format!("schemaVersion is {}, expected 2", m.schema_version)),
            Err(e) => TestOutcome::fail(e),
        }
    }
}

pub struct HelmConfigMediaTypeIsHelm;
impl ComplianceTest for HelmConfigMediaTypeIsHelm {
    fn id(&self) -> &'static str { "helm.config_media_type_is_helm" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let Some(bytes) = manifest_bytes(target) else {
            return TestOutcome::fail("target is not a helm manifest");
        };
        match parse(bytes) {
            Ok(m) => match m.config.and_then(|c| c.media_type) {
                Some(mt) if mt == HELM_CONFIG_MEDIA_TYPE => TestOutcome::pass(),
                Some(mt) => TestOutcome::fail(format!(
                    "config.mediaType {mt:?} is not {HELM_CONFIG_MEDIA_TYPE:?}"
                )),
                None => TestOutcome::fail("config.mediaType missing"),
            },
            Err(e) => TestOutcome::fail(e),
        }
    }
}

pub struct HelmConfigDigestIsSha256;
impl ComplianceTest for HelmConfigDigestIsSha256 {
    fn id(&self) -> &'static str { "helm.config_digest_is_sha256" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let Some(bytes) = manifest_bytes(target) else {
            return TestOutcome::fail("target is not a helm manifest");
        };
        match parse(bytes) {
            Ok(m) => match m.config.and_then(|c| c.digest) {
                Some(d) if d.starts_with("sha256:") && d.len() == "sha256:".len() + 64 => {
                    TestOutcome::pass()
                }
                Some(d) => TestOutcome::fail(format!("config.digest {d:?} not sha256:<64hex>")),
                None => TestOutcome::fail("config.digest missing"),
            },
            Err(e) => TestOutcome::fail(e),
        }
    }
}

pub struct HelmLayersAreSha256Pinned;
impl ComplianceTest for HelmLayersAreSha256Pinned {
    fn id(&self) -> &'static str { "helm.layers_are_sha256_pinned" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let Some(bytes) = manifest_bytes(target) else {
            return TestOutcome::fail("target is not a helm manifest");
        };
        match parse(bytes) {
            Ok(m) => {
                if m.layers.is_empty() {
                    return TestOutcome::fail("helm manifest must have at least one layer (the chart .tar.gz)");
                }
                for (i, layer) in m.layers.iter().enumerate() {
                    let d = layer.digest.as_deref().unwrap_or("");
                    if !d.starts_with("sha256:") || d.len() != "sha256:".len() + 64 {
                        return TestOutcome::fail(format!(
                            "layer[{i}].digest {d:?} not sha256-pinned"
                        ));
                    }
                }
                TestOutcome::pass()
            }
            Err(e) => TestOutcome::fail(e),
        }
    }
}

pub struct HelmLayersUseHelmMediaTypes;
impl ComplianceTest for HelmLayersUseHelmMediaTypes {
    fn id(&self) -> &'static str { "helm.layers_use_helm_media_types" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let Some(bytes) = manifest_bytes(target) else {
            return TestOutcome::fail("target is not a helm manifest");
        };
        match parse(bytes) {
            Ok(m) => {
                for (i, layer) in m.layers.iter().enumerate() {
                    let mt = layer.media_type.as_deref().unwrap_or("");
                    if !HELM_LAYER_MEDIA_TYPES.contains(&mt) {
                        return TestOutcome::fail(format!(
                            "layer[{i}].mediaType {mt:?} is not on the helm allowlist"
                        ));
                    }
                }
                TestOutcome::pass()
            }
            Err(e) => TestOutcome::fail(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(json: &str) -> Target {
        Target::from_helm_manifest_bytes(json.as_bytes().to_vec())
    }

    const GOOD_HELM: &str = r#"{
      "schemaVersion": 2,
      "config": {
        "mediaType": "application/vnd.cncf.helm.config.v1+json",
        "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "size": 100
      },
      "layers": [
        {"mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip", "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111", "size": 1000}
      ]
    }"#;

    #[test]
    fn good_helm_passes_every_test() {
        assert!(HelmSchemaVersionIsTwo.run(&t(GOOD_HELM)).is_pass());
        assert!(HelmConfigMediaTypeIsHelm.run(&t(GOOD_HELM)).is_pass());
        assert!(HelmConfigDigestIsSha256.run(&t(GOOD_HELM)).is_pass());
        assert!(HelmLayersAreSha256Pinned.run(&t(GOOD_HELM)).is_pass());
        assert!(HelmLayersUseHelmMediaTypes.run(&t(GOOD_HELM)).is_pass());
    }

    #[test]
    fn config_with_oci_image_media_type_fails_helm_check() {
        let oci_media = r#"{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":1}}"#;
        assert!(matches!(
            HelmConfigMediaTypeIsHelm.run(&t(oci_media)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn empty_layers_fail_pinning_for_helm() {
        let bare = r#"{"schemaVersion":2,"layers":[]}"#;
        assert!(matches!(
            HelmLayersAreSha256Pinned.run(&t(bare)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn non_helm_layer_media_type_fails() {
        let bad = r#"{
          "schemaVersion": 2,
          "layers": [{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}]
        }"#;
        assert!(matches!(
            HelmLayersUseHelmMediaTypes.run(&t(bad)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn target_oci_returns_fail_for_helm_tests() {
        let oci = Target::from_oci_manifest_bytes(b"{}".to_vec());
        for test in [
            &HelmSchemaVersionIsTwo as &dyn ComplianceTest,
            &HelmConfigMediaTypeIsHelm,
            &HelmConfigDigestIsSha256,
            &HelmLayersAreSha256Pinned,
            &HelmLayersUseHelmMediaTypes,
        ] {
            assert!(matches!(test.run(&oci), TestOutcome::Fail { .. }));
        }
    }
}
