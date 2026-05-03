//! `Target` enum — what a `ComplianceTest` runs against. Today: OCI
//! manifest bytes. Phase 2: helm chart, bundle.

#[derive(Debug, Clone)]
pub enum Target {
    /// Raw bytes of an OCI manifest. Tests parse them.
    OciManifest { bytes: Vec<u8> },
}

impl Target {
    /// Convenience constructor.
    #[must_use]
    pub fn from_oci_manifest_bytes(bytes: Vec<u8>) -> Self {
        Self::OciManifest { bytes }
    }
}
