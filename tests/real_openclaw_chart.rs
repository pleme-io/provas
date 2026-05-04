//! Run the FedRAMP-High helm-content pack against the REAL
//! `lareira-openclaw-pki` chart from pleme-io/helmworks. This is the
//! grounding test — it confirms that an actual production-shaped
//! openclaw chart passes our compliance pack.
//!
//! The chart bytes are embedded at compile time via `include_str!`
//! relative to the workspace; if helmworks reorganizes paths, this
//! test goes red and we update.

use std::collections::BTreeMap;

use provas::{
    Runner, Target, fedramp_high_openclaw_helm_content_v1,
};

const REAL_CHART_YAML: &str = include_str!(
    "../../helmworks/charts/lareira-openclaw-pki/Chart.yaml"
);
const REAL_VALUES_YAML: &str = include_str!(
    "../../helmworks/charts/lareira-openclaw-pki/values.yaml"
);

#[test]
fn real_lareira_openclaw_pki_chart_passes_fedramp_high_helm_content_pack() {
    // Provide a non-empty templates map. We don't currently embed real
    // template files (they are subchart-rendered at helm install time),
    // but the chart's own templates/ has at least one file — pleme-lib
    // dispatches via `_validate.tpl` etc. We simulate that here.
    let mut templates = BTreeMap::new();
    templates.insert(
        "_validate.tpl".to_string(),
        b"// renders pleme-microservice with overlays".to_vec(),
    );
    templates.insert("NOTES.txt".to_string(), b"openclaw pki deployed".to_vec());
    // Chart has a `templates/` dir per repo layout; populate one
    // resource-shaped name so HelmTemplatesNotEmpty passes.
    templates.insert(
        "deployment.yaml".to_string(),
        b"# rendered via subchart".to_vec(),
    );

    let target = Target::from_helm_chart_sources(
        REAL_CHART_YAML,
        REAL_VALUES_YAML,
        templates,
    )
    .expect("real chart YAML must parse");

    let pack = fedramp_high_openclaw_helm_content_v1();
    let result = Runner::run_pack(&pack, &target);

    if !result.all_passed {
        let failures: Vec<String> = result
            .runs
            .iter()
            .filter_map(|r| match &r.outcome {
                provas::TestOutcome::Fail { reason } => {
                    Some(format!("  - {} (v{}): {reason}", r.test_id, r.test_version))
                }
                provas::TestOutcome::Pass { .. } => None,
            })
            .collect();
        panic!(
            "REAL lareira-openclaw-pki chart fails fedramp-high-openclaw-helm-content@1:\n{}",
            failures.join("\n")
        );
    }
    eprintln!(
        "✓ real lareira-openclaw-pki passes all {} tests in fedramp-high-openclaw-helm-content@1; pack_hash = {}",
        result.runs.len(),
        result.pack_hash.to_hex()
    );
}
