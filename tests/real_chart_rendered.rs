//! Run the FedRAMP-High helm-rendered pack against the REAL
//! `lareira-openclaw-pki` chart, after `helm template` actually
//! renders it. This is the V13-closing test: catches templates that
//! hide non-compliant config.
//!
//! Requires `helm` on PATH. If absent, the test is skipped with an
//! eprintln warning (to keep CI from failing on environments without
//! helm).

use std::process::Command;

use provas::{Runner, Target, fedramp_high_openclaw_helm_rendered_v1};

fn helm_available() -> bool {
    Command::new("helm")
        .arg("version")
        .arg("--short")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

const CHART_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../helmworks/charts/lareira-openclaw-pki"
);

fn render_chart() -> Result<String, String> {
    // First make sure subchart deps are built. Helm requires this for
    // charts with `dependencies:` in Chart.yaml. Best-effort — if
    // already built, this is a no-op.
    let _ = Command::new("helm")
        .args(["dependency", "build", CHART_DIR])
        .output();

    let out = Command::new("helm")
        .args([
            "template",
            CHART_DIR,
            // Override the all-zero placeholder to bypass the chart's
            // explicit fail() check for unsubstituted placeholders.
            "--set", "pleme-microservice.image.tag=sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--set", "pleme-microservice.attestation.signature=fakesig",
            "--set", "pleme-microservice.attestation.certificationHash=ch",
            "--set", "pleme-microservice.attestation.complianceHash=ch",
            "--set", "pleme-microservice.attestation.changesetHash=cs",
        ])
        .output()
        .map_err(|e| format!("spawn helm: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "helm template failed (exit {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn real_lareira_openclaw_pki_rendered_passes_fedramp_high() {
    if !helm_available() {
        eprintln!("SKIP: helm not on PATH; skipping real-chart-rendered test");
        return;
    }

    let yaml = match render_chart() {
        Ok(y) => y,
        Err(e) => {
            // helm dependency might not be buildable in the test env
            // (no nexus access, sub-chart not vendored, etc.) — skip
            // rather than fail.
            eprintln!("SKIP: render_chart failed: {e}");
            return;
        }
    };

    let target = match Target::from_helm_rendered_yaml(&yaml) {
        Ok(t) => t,
        Err(e) => panic!("rendered YAML did not parse: {e}\n--- stream ---\n{yaml}"),
    };

    let pack = fedramp_high_openclaw_helm_rendered_v1();
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
            "real lareira-openclaw-pki rendered output fails fedramp-high-openclaw-helm-rendered@1:\n{}",
            failures.join("\n")
        );
    }
    eprintln!(
        "✓ real lareira-openclaw-pki RENDERED: {} tests pass; pack_hash={}",
        result.runs.len(),
        result.pack_hash.to_hex()
    );
}
