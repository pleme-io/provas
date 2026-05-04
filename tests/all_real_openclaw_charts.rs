//! Run the FedRAMP-High helm-content pack against EVERY real
//! `lareira-openclaw-*` chart in helmworks. This sweeps the openclaw
//! family looking for genuine FedRAMP-High violations in production
//! code. Each chart is embedded at compile time; if any fails, the
//! pack output names the failing test + reason so the chart can be
//! fixed before this test goes green.
//!
//! Already caught (and fixed): `:latest` reference in
//! `lareira-openclaw-pki`. This test pre-empts the next regression.

use std::collections::BTreeMap;

use provas::{Runner, Target, fedramp_high_openclaw_helm_content_v1};

fn run_pack_or_fail(chart_yaml: &str, values_yaml: &str, chart_name: &str) {
    let mut templates = BTreeMap::new();
    templates.insert("_validate.tpl".into(), b"".to_vec());
    templates.insert("NOTES.txt".into(), b"".to_vec());
    templates.insert("deployment.yaml".into(), b"# rendered".to_vec());

    let target = Target::from_helm_chart_sources(chart_yaml, values_yaml, templates)
        .unwrap_or_else(|e| panic!("{chart_name}: chart parse error: {e}"));

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
            "{chart_name} fails fedramp-high-openclaw-helm-content@1:\n{}",
            failures.join("\n")
        );
    }
    eprintln!(
        "✓ {chart_name}: {} tests pass; pack_hash={}",
        result.runs.len(),
        result.pack_hash.to_hex()
    );
}

const OPENCLAW_CHART_YAML: &str = include_str!("../../helmworks/charts/lareira-openclaw/Chart.yaml");
const OPENCLAW_VALUES: &str = include_str!("../../helmworks/charts/lareira-openclaw/values.yaml");

const PKI_CHART_YAML: &str = include_str!("../../helmworks/charts/lareira-openclaw-pki/Chart.yaml");
const PKI_VALUES: &str = include_str!("../../helmworks/charts/lareira-openclaw-pki/values.yaml");

const SCANNER_CHART_YAML: &str =
    include_str!("../../helmworks/charts/lareira-openclaw-scanner/Chart.yaml");
const SCANNER_VALUES: &str =
    include_str!("../../helmworks/charts/lareira-openclaw-scanner/values.yaml");

const STORE_CHART_YAML: &str =
    include_str!("../../helmworks/charts/lareira-openclaw-store/Chart.yaml");
const STORE_VALUES: &str =
    include_str!("../../helmworks/charts/lareira-openclaw-store/values.yaml");

const STACK_CHART_YAML: &str =
    include_str!("../../helmworks/charts/lareira-openclaw-stack/Chart.yaml");
const STACK_VALUES: &str =
    include_str!("../../helmworks/charts/lareira-openclaw-stack/values.yaml");

#[test]
fn lareira_openclaw_passes_fedramp_high() {
    run_pack_or_fail(OPENCLAW_CHART_YAML, OPENCLAW_VALUES, "lareira-openclaw");
}

#[test]
fn lareira_openclaw_pki_passes_fedramp_high() {
    run_pack_or_fail(PKI_CHART_YAML, PKI_VALUES, "lareira-openclaw-pki");
}

#[test]
fn lareira_openclaw_scanner_passes_fedramp_high() {
    run_pack_or_fail(SCANNER_CHART_YAML, SCANNER_VALUES, "lareira-openclaw-scanner");
}

#[test]
fn lareira_openclaw_store_passes_fedramp_high() {
    run_pack_or_fail(STORE_CHART_YAML, STORE_VALUES, "lareira-openclaw-store");
}

#[test]
fn lareira_openclaw_stack_passes_fedramp_high() {
    run_pack_or_fail(STACK_CHART_YAML, STACK_VALUES, "lareira-openclaw-stack");
}
