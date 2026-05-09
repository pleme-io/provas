//! Run the FedRAMP-High helm-content pack against the REAL
//! `lareira-openclaw-agent` chart from pleme-io/helmworks. Companion
//! to `real_openclaw_chart` (which exercises the PKI chart) — this is
//! the agent that's actually deployed at openclaw-agent-dev.quero.cloud.
//! If this test goes red, the demo's "actual openclaw passes the
//! actual FedRAMP-High pack" claim is broken and we update the chart.

use std::collections::BTreeMap;

use provas::{Runner, Target, fedramp_high_openclaw_helm_content_v1};

const REAL_CHART_YAML: &str =
    include_str!("../../helmworks/charts/lareira-openclaw-agent/Chart.yaml");
const REAL_VALUES_YAML: &str =
    include_str!("../../helmworks/charts/lareira-openclaw-agent/values.yaml");

#[test]
fn real_lareira_openclaw_agent_chart_passes_fedramp_high_helm_content_pack() {
    // Mirror the placeholder templates pattern used by the PKI test —
    // the real templates are subchart-rendered at install time, but
    // the chart's own templates/ has at least one file each.
    let mut templates = BTreeMap::new();
    templates.insert(
        "_helpers.tpl".to_string(),
        b"// label + name helpers".to_vec(),
    );
    templates.insert(
        "_validate.tpl".to_string(),
        b"// validate.digest + validate.attestation".to_vec(),
    );
    templates.insert(
        "validations.yaml".to_string(),
        b"// defense-in-depth gates".to_vec(),
    );
    templates.insert(
        "deployment.yaml".to_string(),
        b"# rendered via subchart".to_vec(),
    );

    let target =
        Target::from_helm_chart_sources(REAL_CHART_YAML, REAL_VALUES_YAML, templates)
            .expect("real chart YAML must parse");

    let pack = fedramp_high_openclaw_helm_content_v1();
    let result = Runner::run_pack(&pack, &target);

    if !result.all_passed {
        let failures: Vec<String> = result
            .runs
            .iter()
            .filter_map(|r| match &r.outcome {
                provas::TestOutcome::Fail { reason } => Some(format!(
                    "  - {} (v{}): {reason}",
                    r.test_id, r.test_version
                )),
                provas::TestOutcome::Pass { .. } => None,
            })
            .collect();
        panic!(
            "REAL lareira-openclaw-agent chart fails fedramp-high-openclaw-helm-content@1:\n{}",
            failures.join("\n")
        );
    }
    eprintln!(
        "✓ real lareira-openclaw-agent passes all {} tests in fedramp-high-openclaw-helm-content@1; pack_hash = {}",
        result.runs.len(),
        result.pack_hash.to_hex()
    );
}
