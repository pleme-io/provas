//! provas-verify — independent compliance-proof verifier.
//!
//! Given a cartorio URL + an artifact digest, this binary:
//!   1. fetches the artifact's `ArtifactState` from cartorio
//!   2. fetches the manifest bytes from a registry (if URL supplied)
//!      or accepts them from --manifest-file
//!   3. resolves the named pack from the artifact's
//!      `compliance.profile` field
//!   4. re-runs the pack against the bytes
//!   5. compares the recomputed `pack_hash` to the stored
//!      `result_hash`
//!   6. exits 0 if match, non-zero if mismatch (with a per-test diff)
//!
//! Anyone running this binary against a public cartorio + public
//! registry has full proof of the compliance claim. No trust in
//! pleme-io required.

#![allow(clippy::doc_markdown, clippy::needless_pass_by_value)]

use std::fs;
use std::process::ExitCode;

use clap::Parser;
use provas::{
    Pack, Runner, Target, fedramp_high_openclaw_bundle_v1,
    fedramp_high_openclaw_helm_content_v1, fedramp_high_openclaw_helm_v1,
    fedramp_high_openclaw_image_v1, fedramp_high_openclaw_image_v2,
};
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(version, about = "Independent compliance-proof verifier — re-derives the pack_hash from public inputs and confirms it matches what cartorio holds.")]
struct Args {
    /// Cartorio base URL.
    #[arg(long, env = "PROVAS_CARTORIO_URL")]
    cartorio: String,

    /// Artifact digest (sha256:hex64) to verify.
    #[arg(long)]
    digest: String,

    /// Path to the artifact's manifest bytes for re-running the pack.
    /// If `--manifest-file` is omitted, the verifier prints the
    /// stored proof but cannot re-derive — exits with warning.
    #[arg(long)]
    manifest_file: Option<String>,

    /// Verbose: print every test's outcome, not just the summary.
    #[arg(long)]
    verbose: bool,
}

#[derive(Debug, Deserialize)]
struct ArtifactState {
    id: String,
    kind: String,
    digest: String,
    name: String,
    version: String,
    org: String,
    status: String,
    attestation: AttestationChain,
}

#[derive(Debug, Deserialize)]
struct AttestationChain {
    compliance: Option<ComplianceAttestation>,
}

#[derive(Debug, Deserialize)]
struct ComplianceAttestation {
    framework: String,
    baseline: String,
    profile: String,
    result_hash: String,
    status: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    eprintln!("provas-verify — independent compliance-proof verifier");
    eprintln!("  cartorio:  {}", args.cartorio);
    eprintln!("  digest:    {}", args.digest);

    // 1. Fetch ArtifactState.
    let url = format!(
        "{}/api/v1/artifacts/by-digest/{}",
        args.cartorio.trim_end_matches('/'),
        urlencode(&args.digest)
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("reqwest client");
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("FAIL: cartorio request failed: {e}");
            return ExitCode::from(2);
        }
    };
    if !resp.status().is_success() {
        eprintln!(
            "FAIL: cartorio returned {} for digest {}",
            resp.status(),
            args.digest
        );
        return ExitCode::from(3);
    }
    let artifact: ArtifactState = match resp.json().await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("FAIL: parse cartorio response: {e}");
            return ExitCode::from(4);
        }
    };

    eprintln!();
    eprintln!("ArtifactState found:");
    eprintln!("  id:      {}", artifact.id);
    eprintln!("  kind:    {}", artifact.kind);
    eprintln!("  name:    {}", artifact.name);
    eprintln!("  version: {}", artifact.version);
    eprintln!("  org:     {}", artifact.org);
    eprintln!("  status:  {}", artifact.status);

    let Some(comp) = artifact.attestation.compliance else {
        eprintln!("FAIL: artifact has no compliance attestation");
        return ExitCode::from(5);
    };

    eprintln!();
    eprintln!("Compliance attestation (the proof claim):");
    eprintln!("  framework:   {}", comp.framework);
    eprintln!("  baseline:    {}", comp.baseline);
    eprintln!("  profile:     {}", comp.profile);
    eprintln!("  status:      {}", comp.status);
    eprintln!("  result_hash: {}", comp.result_hash);

    if artifact.status != "active" {
        eprintln!();
        eprintln!("WARN: artifact status is {:?}, not active", artifact.status);
    }

    // 2. Resolve pack.
    let pack = match resolve_pack(&comp.profile) {
        Some(p) => p,
        None => {
            eprintln!();
            eprintln!(
                "FAIL: don't know how to resolve pack {:?} (this verifier only knows the curated pleme-io packs)",
                comp.profile
            );
            return ExitCode::from(6);
        }
    };
    eprintln!();
    eprintln!("Pack resolved: {} v{} ({} tests)", pack.id, pack.version, pack.tests.len());

    // 3. Re-run the pack against the bytes (if provided).
    let Some(manifest_path) = args.manifest_file else {
        eprintln!();
        eprintln!("INFO: no --manifest-file provided; printing stored proof only.");
        eprintln!("      To verify, supply the artifact's bytes via --manifest-file.");
        return ExitCode::SUCCESS;
    };
    let bytes = match fs::read(&manifest_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("FAIL: read manifest file {manifest_path}: {e}");
            return ExitCode::from(7);
        }
    };
    eprintln!();
    eprintln!("Manifest file: {manifest_path} ({} bytes)", bytes.len());

    // Sanity: hash of the bytes should equal the artifact digest.
    let actual_digest = sha256_digest(&bytes);
    if actual_digest != artifact.digest {
        eprintln!(
            "FAIL: bytes hash {actual_digest} does not match artifact digest {} — wrong file?",
            artifact.digest
        );
        return ExitCode::from(8);
    }
    eprintln!("✓ manifest bytes hash matches artifact digest ({actual_digest})");

    // Build the right Target shape based on kind / pack id.
    let target = match build_target(&artifact.kind, &pack.id, bytes) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("FAIL: cannot build Target for kind={} pack={}: {e}", artifact.kind, pack.id);
            return ExitCode::from(9);
        }
    };

    let result = Runner::run_pack(&pack, &target);

    eprintln!();
    if args.verbose {
        eprintln!("Per-test outcomes:");
        for r in &result.runs {
            let status = match &r.outcome {
                provas::TestOutcome::Pass { evidence: None } => "PASS".to_string(),
                provas::TestOutcome::Pass { evidence: Some(e) } => format!("PASS  ({e})"),
                provas::TestOutcome::Fail { reason } => format!("FAIL  {reason}"),
            };
            eprintln!("  [{}] {} (v{}) — {}", if r.outcome.is_pass() { "✓" } else { "✗" }, r.test_id, r.test_version, status);
        }
        eprintln!();
    }

    if !result.all_passed {
        eprintln!("FAIL: pack run produced one or more Fail outcomes — proof is broken");
        return ExitCode::from(10);
    }

    let computed = result.pack_hash.to_hex();
    if computed != comp.result_hash {
        eprintln!("FAIL: recomputed pack_hash mismatch");
        eprintln!("      stored:    {}", comp.result_hash);
        eprintln!("      recomputed: {computed}");
        eprintln!();
        eprintln!("This means the artifact's compliance claim is forged or one of:");
        eprintln!("  - the artifact bytes have been tampered with");
        eprintln!("  - the pack source code has changed (pack version mismatch?)");
        eprintln!("  - cartorio was lied to at admission time");
        return ExitCode::from(11);
    }

    eprintln!("✓ recomputed pack_hash matches stored result_hash: {computed}");
    eprintln!();
    eprintln!("PROOF VERIFIED. {} v{} is provably {} {} compliant.", artifact.name, artifact.version, comp.framework, comp.baseline);
    ExitCode::SUCCESS
}

fn resolve_pack(profile: &str) -> Option<Pack> {
    match profile {
        "fedramp-high-openclaw-image@1" => Some(fedramp_high_openclaw_image_v1()),
        "fedramp-high-openclaw-image@2" => Some(fedramp_high_openclaw_image_v2()),
        "fedramp-high-openclaw-helm@1" => Some(fedramp_high_openclaw_helm_v1()),
        "fedramp-high-openclaw-helm-content@1" => Some(fedramp_high_openclaw_helm_content_v1()),
        "fedramp-high-openclaw-bundle@1" => Some(fedramp_high_openclaw_bundle_v1()),
        _ => None,
    }
}

fn build_target(kind: &str, pack_id: &str, bytes: Vec<u8>) -> Result<Target, String> {
    if pack_id.contains("helm-content") {
        return Err("helm-content packs require structured chart sources, not just manifest bytes — supply Chart.yaml/values.yaml/templates separately (not yet supported in this CLI)".into());
    }
    if pack_id.contains("bundle") {
        return Err("bundle packs require member triples, not raw manifest bytes — see verify-bundle subcommand (not yet implemented)".into());
    }
    match kind {
        "oci-image" => Ok(Target::from_oci_manifest_bytes(bytes)),
        "helm-chart" => Ok(Target::from_helm_manifest_bytes(bytes)),
        other => Err(format!("don't know how to build Target for kind {other:?}")),
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{}", hex::encode(h.finalize()))
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}
