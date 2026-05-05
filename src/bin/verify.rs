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

#![allow(
    clippy::doc_markdown,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::manual_let_else,
    clippy::single_match_else
)]

use std::fs;
use std::process::ExitCode;

use clap::Parser;
use provas::{
    Pack, Runner, Target, fedramp_high_openclaw_bundle_v1,
    fedramp_high_openclaw_helm_content_v1, fedramp_high_openclaw_helm_rendered_v1,
    fedramp_high_openclaw_helm_v1, fedramp_high_openclaw_image_v1,
    fedramp_high_openclaw_image_v2,
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

    /// For helm-content packs: path to the chart's `Chart.yaml`.
    #[arg(long)]
    chart_yaml: Option<String>,

    /// For helm-content packs: path to the chart's `values.yaml`.
    #[arg(long)]
    values_yaml: Option<String>,

    /// For bundle packs: comma-separated list of `digest:kind:pack_hash_hex`
    /// triples for each member. e.g.
    /// `--bundle-members sha256:abc:oci-image:dead...,sha256:def:helm-chart:beef...`
    #[arg(long, value_delimiter = ',')]
    bundle_members: Vec<String>,

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

    // 3. Build the right Target based on pack type.
    let target = if pack.id.contains("helm-content") {
        match build_helm_content_target(&args) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("FAIL: helm-content target: {e}");
                eprintln!("      Supply --chart-yaml + --values-yaml to verify a helm-content pack.");
                return ExitCode::from(7);
            }
        }
    } else if pack.id.contains("bundle") {
        match build_bundle_target(&args) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("FAIL: bundle target: {e}");
                eprintln!("      Supply --bundle-members <list> to verify a bundle pack.");
                return ExitCode::from(7);
            }
        }
    } else {
        // OCI image or helm-as-OCI manifest.
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
        let actual_digest = sha256_digest(&bytes);
        if actual_digest != artifact.digest {
            eprintln!(
                "FAIL: bytes hash {actual_digest} does not match artifact digest {} — wrong file?",
                artifact.digest
            );
            return ExitCode::from(8);
        }
        eprintln!("✓ manifest bytes hash matches artifact digest ({actual_digest})");
        match build_target(&artifact.kind, &pack.id, bytes) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("FAIL: cannot build Target for kind={} pack={}: {e}", artifact.kind, pack.id);
                return ExitCode::from(9);
            }
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
        "fedramp-high-openclaw-helm-rendered@1" => Some(fedramp_high_openclaw_helm_rendered_v1()),
        "fedramp-high-openclaw-bundle@1" => Some(fedramp_high_openclaw_bundle_v1()),
        _ => None,
    }
}

fn build_target(kind: &str, _pack_id: &str, bytes: Vec<u8>) -> Result<Target, String> {
    match kind {
        "oci-image" => Ok(Target::from_oci_manifest_bytes(bytes)),
        "helm-chart" => Ok(Target::from_helm_manifest_bytes(bytes)),
        other => Err(format!("don't know how to build Target for kind {other:?}")),
    }
}

fn build_helm_content_target(args: &Args) -> Result<Target, String> {
    let chart_path = args
        .chart_yaml
        .as_ref()
        .ok_or_else(|| "missing --chart-yaml".to_string())?;
    let values_path = args
        .values_yaml
        .as_ref()
        .ok_or_else(|| "missing --values-yaml".to_string())?;
    let chart =
        fs::read_to_string(chart_path).map_err(|e| format!("read {chart_path}: {e}"))?;
    let values =
        fs::read_to_string(values_path).map_err(|e| format!("read {values_path}: {e}"))?;
    // Templates not loaded by this CLI (would require directory walk);
    // most helm-content tests don't depend on them today.
    let templates = std::collections::BTreeMap::new();
    Target::from_helm_chart_sources(&chart, &values, templates)
        .map_err(|e| format!("yaml parse: {e}"))
}

fn build_bundle_target(args: &Args) -> Result<Target, String> {
    if args.bundle_members.is_empty() {
        return Err("missing --bundle-members".into());
    }
    let mut members = Vec::with_capacity(args.bundle_members.len());
    for entry in &args.bundle_members {
        let parts: Vec<&str> = entry.splitn(3, ':').collect();
        // entry is `sha256:HEX:KIND:PACKHASH_HEX` — splitting on : gives
        // the digest split at "sha256:HEX" plus the rest. Re-split.
        let entry = entry.as_str();
        let kind_idx = entry
            .find(":oci-image:")
            .or_else(|| entry.find(":helm-chart:"))
            .or_else(|| entry.find(":skill:"))
            .or_else(|| entry.find(":bundle:"))
            .ok_or_else(|| {
                format!(
                    "entry {entry:?} does not contain a kind separator (:oci-image:|:helm-chart:|:skill:|:bundle:); got {} parts",
                    parts.len()
                )
            })?;
        let digest = entry[..kind_idx].to_string();
        let after = &entry[kind_idx + 1..]; // skip the leading ':'
        let (kind, hash_hex) = after
            .split_once(':')
            .ok_or_else(|| format!("entry {entry:?} missing pack_hash after kind"))?;
        let hash_bytes = hex::decode(hash_hex)
            .map_err(|e| format!("entry {entry:?} pack_hash hex: {e}"))?;
        let arr: [u8; 32] = hash_bytes
            .try_into()
            .map_err(|_| format!("entry {entry:?} pack_hash not 32 bytes"))?;
        members.push(provas::BundleMember {
            digest,
            kind: kind.to_string(),
            pack_hash: tameshi::hash::Blake3Hash(arr),
        });
    }
    Ok(Target::from_bundle_members(members))
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
