//! `Target` enum — what a `ComplianceTest` runs against.

use tameshi::hash::Blake3Hash;

#[derive(Debug, Clone)]
pub enum Target {
    /// Raw bytes of an OCI manifest (image push).
    OciManifest { bytes: Vec<u8> },

    /// Raw bytes of a Helm-as-OCI manifest (helm push). Same wire
    /// format as OCI image manifests; what differs is the expected
    /// `config.mediaType` (`application/vnd.cncf.helm.config.v1+json`).
    HelmManifest { bytes: Vec<u8> },

    /// A composed deployable: ordered list of (digest, kind,
    /// `pack_hash`) tuples for each member. Bundle tests verify
    /// shape + member proof presence; the test outcomes carry the
    /// member `pack_hash`es as evidence so the bundle's own
    /// `pack_hash` is data-bound (different members → different
    /// bundle `pack_hash`).
    Bundle { members: Vec<BundleMember> },
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
}
