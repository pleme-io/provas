//! End-to-end test of the `provas-verify` binary against a live
//! cartorio instance. Spins up cartorio in-process, admits an
//! artifact, then invokes the verifier CLI as a subprocess and
//! checks exit code + stdout/stderr.
//!
//! This is the "the CLI actually works" check — complements the lib
//! tests by exercising the full binary path including argument
//! parsing, HTTP fetch, file IO, and exit codes.

#![allow(clippy::too_many_lines)]

use std::process::Command;

use cartorio::api::router as cartorio_router;
use cartorio::config::RegistryConfig;
use cartorio::core::types::{ArtifactKind, ComplianceStatus};
use cartorio::state::AppState;
use tabeliao::AttestationsConfig;
use tabeliao::attestations::{
    AttestationsBlock, BuildBlock, ComplianceBlock, ImageBlock, SourceBlock,
};
use tabeliao::sign::Ed25519Signer;
use tameshi::hash::Blake3Hash;

const ORG: &str = "pleme-io";

const COMPLIANT_OCI_MANIFEST: &[u8] = br#"{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "size": 100
  },
  "layers": [
    {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111", "size": 5000}
  ],
  "annotations": {
    "io.pleme.slsa-provenance-ref": "ghcr.io/pleme-io/x@sha256:beef"
  }
}"#;

async fn spawn_cartorio() -> String {
    let cfg = RegistryConfig {
        org: ORG.into(),
        listen: "127.0.0.1:0".into(),
        pki_url: None,
    };
    let state = AppState::new(cfg);
    let app = cartorio_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    url
}

fn cfg_for(name: &str, version: &str) -> AttestationsConfig {
    AttestationsConfig {
        kind: ArtifactKind::OciImage,
        name: name.into(),
        version: version.into(),
        publisher_id: "alice@pleme.io".into(),
        org: ORG.into(),
        attestation: AttestationsBlock {
            source: Some(SourceBlock {
                git_commit: "abc".into(),
                tree_hash: Blake3Hash::digest(b"tree"),
                flake_lock_hash: Blake3Hash::digest(b"lock"),
            }),
            build: Some(BuildBlock {
                closure_hash: Blake3Hash::digest(b"closure"),
                sbom_hash: Blake3Hash::digest(b"sbom"),
                slsa_level: 3,
            }),
            image: Some(ImageBlock {
                cosign_signature_ref: "ghcr.io/x:sig".into(),
                slsa_provenance_ref: "ghcr.io/x:prov".into(),
            }),
            compliance: Some(ComplianceBlock {
                framework: "FedRAMP".into(),
                baseline: "high".into(),
                profile: "fedramp-high-openclaw-image@1".into(),
                result_hash: Blake3Hash::digest(b"placeholder"),
                status: ComplianceStatus::Compliant,
            }),
        },
    }
}

async fn admit_compliant_image(cartorio_url: &str) -> (String, std::path::PathBuf) {
    // Run image pack, splice into compliance block, sign, admit.
    let signer = Ed25519Signer::generate();
    let pack = tabeliao::compliance::pack_by_name("fedramp-high-openclaw-image@1").unwrap();
    let pack_hash = tabeliao::compliance::enforce_pack(&pack, COMPLIANT_OCI_MANIFEST).unwrap();

    let mut cfg = cfg_for("test-image", "1.0.0");
    cfg.attestation.compliance = Some(ComplianceBlock {
        framework: "FedRAMP".into(),
        baseline: "high".into(),
        profile: "fedramp-high-openclaw-image@1".into(),
        result_hash: pack_hash,
        status: ComplianceStatus::Compliant,
    });

    let digest = tabeliao::publish::manifest_digest(COMPLIANT_OCI_MANIFEST);
    let admit_input = tabeliao::admit::build_admit_input(
        cfg,
        &digest,
        chrono::Utc::now(),
        &signer,
    )
    .unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{cartorio_url}/api/v1/artifacts"))
        .json(&admit_input)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "admit failed: {}", resp.text().await.unwrap());

    // Write the manifest bytes to a temp file for the verifier to read.
    let tmp = std::env::temp_dir().join(format!("provas-verify-e2e-{digest}.json"));
    std::fs::write(&tmp, COMPLIANT_OCI_MANIFEST).unwrap();
    (digest, tmp)
}

fn provas_verify_bin() -> String {
    env!("CARGO_BIN_EXE_provas-verify").to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provas_verify_succeeds_against_live_cartorio_with_compliant_artifact() {
    let cartorio_url = spawn_cartorio().await;
    let (digest, manifest_path) = admit_compliant_image(&cartorio_url).await;

    let output = Command::new(provas_verify_bin())
        .args([
            "--cartorio",
            &cartorio_url,
            "--digest",
            &digest,
            "--manifest-file",
            manifest_path.to_str().unwrap(),
            "--verbose",
        ])
        .output()
        .expect("spawn provas-verify");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!("--- stderr ---\n{stderr}");
    eprintln!("--- stdout ---\n{stdout}");

    assert!(
        output.status.success(),
        "provas-verify must exit 0 for a valid proof; got {} (stderr above)",
        output.status
    );
    // Headline strings from the verifier's success path.
    assert!(stderr.contains("PROOF VERIFIED"));
    assert!(stderr.contains("recomputed pack_hash matches stored result_hash"));
    // Verbose mode: every test should be logged with PASS.
    assert!(stderr.contains("oci.schema_version_is_two"));

    // Cleanup.
    std::fs::remove_file(&manifest_path).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provas_verify_fails_on_tampered_manifest_with_useful_diff() {
    let cartorio_url = spawn_cartorio().await;
    let (digest, _) = admit_compliant_image(&cartorio_url).await;

    // Write a TAMPERED manifest to the file the verifier reads.
    let tampered_path = std::env::temp_dir().join(format!("provas-verify-tampered-{digest}.json"));
    let tampered_bytes = String::from_utf8(COMPLIANT_OCI_MANIFEST.to_vec())
        .unwrap()
        .replace(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "latest",
        )
        .into_bytes();
    std::fs::write(&tampered_path, &tampered_bytes).unwrap();

    let output = Command::new(provas_verify_bin())
        .args([
            "--cartorio",
            &cartorio_url,
            "--digest",
            &digest,
            "--manifest-file",
            tampered_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn provas-verify");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "tampered manifest must produce non-zero exit; got {}",
        output.status
    );
    // The byte hash mismatch is the FIRST gate (we sanity-check the
    // manifest hash matches the artifact digest before running the
    // pack); that's why we expect "bytes hash" in the stderr rather
    // than the pack-failure message.
    assert!(
        stderr.contains("bytes hash") && stderr.contains("does not match artifact digest"),
        "expected manifest-bytes-hash mismatch in stderr; got:\n{stderr}"
    );

    std::fs::remove_file(&tampered_path).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provas_verify_fails_on_unknown_digest_at_cartorio() {
    let cartorio_url = spawn_cartorio().await;
    // No admission — cartorio knows nothing about this digest.
    let bogus_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let manifest_path = std::env::temp_dir().join("provas-verify-unknown.json");
    std::fs::write(&manifest_path, COMPLIANT_OCI_MANIFEST).unwrap();

    let output = Command::new(provas_verify_bin())
        .args([
            "--cartorio",
            &cartorio_url,
            "--digest",
            bogus_digest,
            "--manifest-file",
            manifest_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn provas-verify");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(
        stderr.contains("404") || stderr.contains("not found"),
        "expected 404-shaped error; got:\n{stderr}"
    );

    std::fs::remove_file(&manifest_path).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provas_verify_warns_when_no_manifest_file_supplied() {
    let cartorio_url = spawn_cartorio().await;
    let (digest, manifest_path) = admit_compliant_image(&cartorio_url).await;

    let output = Command::new(provas_verify_bin())
        .args([
            "--cartorio",
            &cartorio_url,
            "--digest",
            &digest,
            // intentionally omit --manifest-file
        ])
        .output()
        .expect("spawn provas-verify");

    // Without --manifest-file, the verifier prints the stored proof
    // but cannot re-derive — exits success with a warning.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "should exit 0 (warning, not error)");
    assert!(
        stderr.contains("no --manifest-file provided") || stderr.contains("printing stored proof"),
        "expected warning about missing manifest; got:\n{stderr}"
    );

    std::fs::remove_file(&manifest_path).ok();
}
