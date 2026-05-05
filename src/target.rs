//! `Target` enum — what a `ComplianceTest` runs against.
#![allow(clippy::doc_markdown, clippy::needless_pass_by_value)]

use std::collections::BTreeMap;

use serde::Deserialize;
use tameshi::hash::Blake3Hash;

#[derive(Debug, Clone)]
pub enum Target {
    /// Raw bytes of an OCI manifest (image push).
    OciManifest { bytes: Vec<u8> },

    /// Raw bytes of a Helm-as-OCI manifest (helm push). Same wire
    /// format as OCI image manifests; what differs is the expected
    /// `config.mediaType` (`application/vnd.cncf.helm.config.v1+json`).
    HelmManifest { bytes: Vec<u8> },

    /// Helm chart contents extracted from the chart bundle: parsed
    /// `Chart.yaml`, parsed `values.yaml`, and a name-to-bytes map of
    /// rendered templates. This is what FedRAMP-High helm content
    /// tests target — they read the chart's actual configuration,
    /// not just its OCI manifest envelope.
    HelmChartContent {
        chart_yaml: serde_yaml_ng::Value,
        values_yaml: serde_yaml_ng::Value,
        templates: BTreeMap<String, Vec<u8>>,
    },

    /// An OpenClaw skill bundle: parsed SKILL.md frontmatter (the
    /// YAML at the top of the file declaring `capabilities`,
    /// `threat_model`, etc.) plus a name-to-bytes map of bundled
    /// files. Tests verify capability declarations, threat-model
    /// fields, etc. — the FedRAMP-High view of an AI skill.
    OpenClawSkill {
        skill_md_frontmatter: serde_yaml_ng::Value,
        files: BTreeMap<String, Vec<u8>>,
    },

    /// A composed deployable: ordered list of (digest, kind,
    /// `pack_hash`) tuples for each member. Bundle tests verify
    /// shape + member proof presence; the test outcomes carry the
    /// member `pack_hash`es as evidence so the bundle's own
    /// `pack_hash` is data-bound (different members → different
    /// bundle `pack_hash`).
    Bundle { members: Vec<BundleMember> },

    /// Rendered helm chart output: `helm template` produces a
    /// multi-document YAML stream of Kubernetes resources. This
    /// target carries each parsed document. Tests walk the
    /// resources looking at PodSpecs, container security contexts,
    /// resource limits, etc. — the controls that values.yaml
    /// inspection cannot catch when templates hide configuration.
    HelmRenderedTemplates { resources: Vec<serde_yaml_ng::Value> },
}

#[derive(Debug, Clone)]
pub struct BundleMember {
    pub digest: String,
    pub kind: String,
    pub pack_hash: Blake3Hash,
}

impl Target {
    /// Convenience constructor.
    #[must_use]
    pub fn from_oci_manifest_bytes(bytes: Vec<u8>) -> Self {
        Self::OciManifest { bytes }
    }

    /// Convenience constructor.
    #[must_use]
    pub fn from_helm_manifest_bytes(bytes: Vec<u8>) -> Self {
        Self::HelmManifest { bytes }
    }

    /// Convenience constructor.
    #[must_use]
    pub fn from_bundle_members(members: Vec<BundleMember>) -> Self {
        Self::Bundle { members }
    }

    /// Parse a `helm template` multi-document YAML stream into
    /// `HelmRenderedTemplates`.
    ///
    /// # Errors
    /// Returns yaml parse errors.
    pub fn from_helm_rendered_yaml(yaml_stream: &str) -> Result<Self, serde_yaml_ng::Error> {
        let mut resources = Vec::new();
        for doc in serde_yaml_ng::Deserializer::from_str(yaml_stream) {
            let value = serde_yaml_ng::Value::deserialize(doc)?;
            // helm template emits `null` documents for empty
            // separator-only sections; skip them.
            if !matches!(value, serde_yaml_ng::Value::Null) {
                resources.push(value);
            }
        }
        Ok(Self::HelmRenderedTemplates { resources })
    }

    /// Parse Chart.yaml + values.yaml strings + templates map into a
    /// `HelmChartContent` target.
    ///
    /// # Errors
    /// Returns yaml parse errors.
    pub fn from_helm_chart_sources(
        chart_yaml: &str,
        values_yaml: &str,
        templates: BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, serde_yaml_ng::Error> {
        Ok(Self::HelmChartContent {
            chart_yaml: serde_yaml_ng::from_str(chart_yaml)?,
            values_yaml: serde_yaml_ng::from_str(values_yaml)?,
            templates,
        })
    }

    /// Parse a SKILL.md file's YAML frontmatter into an
    /// `OpenClawSkill` target. The frontmatter is everything between
    /// the opening `---` and the closing `---`.
    ///
    /// # Errors
    /// Returns errors if frontmatter is missing or malformed.
    pub fn from_skill_md(
        skill_md_text: &str,
        files: BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, String> {
        let frontmatter = extract_frontmatter(skill_md_text)?;
        let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(frontmatter)
            .map_err(|e| format!("SKILL.md frontmatter parse: {e}"))?;
        Ok(Self::OpenClawSkill {
            skill_md_frontmatter: parsed,
            files,
        })
    }
}

fn extract_frontmatter(text: &str) -> Result<&str, String> {
    let trimmed = text.trim_start();
    let after_open = trimmed
        .strip_prefix("---\n")
        .or_else(|| trimmed.strip_prefix("---\r\n"))
        .ok_or_else(|| "SKILL.md must start with `---` frontmatter delimiter".to_string())?;
    let close_idx = after_open
        .find("\n---\n")
        .or_else(|| after_open.find("\n---\r\n"))
        .or_else(|| {
            // Allow EOF after closing fence for one-block files.
            if after_open.ends_with("\n---") {
                Some(after_open.len() - 4)
            } else {
                None
            }
        })
        .ok_or_else(|| "SKILL.md frontmatter has no closing `---` fence".to_string())?;
    Ok(&after_open[..close_idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_frontmatter_basic() {
        let md = "---\nname: x\n---\n\nbody";
        let fm = extract_frontmatter(md).unwrap();
        assert_eq!(fm, "name: x");
    }

    #[test]
    fn extract_frontmatter_missing_open_fence() {
        assert!(extract_frontmatter("name: x\n").is_err());
    }

    #[test]
    fn extract_frontmatter_missing_close_fence() {
        assert!(extract_frontmatter("---\nname: x\n").is_err());
    }

    #[test]
    fn from_skill_md_round_trip() {
        let md = "---\nname: my-skill\nversion: 1.0.0\n---\n\nBody.";
        let t = Target::from_skill_md(md, BTreeMap::new()).unwrap();
        match t {
            Target::OpenClawSkill { skill_md_frontmatter, .. } => {
                assert_eq!(skill_md_frontmatter["name"].as_str().unwrap(), "my-skill");
                assert_eq!(skill_md_frontmatter["version"].as_str().unwrap(), "1.0.0");
            }
            _ => panic!("wrong variant"),
        }
    }
}
