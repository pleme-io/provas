//! Bundle compliance tests — verify a composed deployable.
//!
//! Each test that observes member data emits its observation as
//! `evidence` on Pass. Evidence is part of the `pack_hash`, so two
//! bundles whose members differ produce different bundle
//! `pack_hash`es even though both pass. This is what threads the
//! members' proofs into the bundle's proof.

use crate::runner::{ComplianceTest, TestOutcome};
use crate::target::Target;

const KIND_OCI_IMAGE: &str = "oci-image";
const KIND_HELM_CHART: &str = "helm-chart";

fn members(target: &Target) -> Option<&Vec<crate::target::BundleMember>> {
    match target {
        Target::Bundle { members } => Some(members),
        _ => None,
    }
}

pub struct BundleHasAtLeastOneOciImageMember;
impl ComplianceTest for BundleHasAtLeastOneOciImageMember {
    fn id(&self) -> &'static str { "bundle.has_at_least_one_oci_image_member" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let Some(ms) = members(target) else {
            return TestOutcome::fail("target is not a bundle");
        };
        let imgs: Vec<&crate::target::BundleMember> = ms.iter().filter(|m| m.kind == KIND_OCI_IMAGE).collect();
        if imgs.is_empty() {
            return TestOutcome::fail("bundle has no oci-image members");
        }
        // Evidence: sorted (digest:pack_hash) pairs for every image member.
        // This binds the bundle pack_hash to the specific images
        // admitted, so changing the image changes the bundle proof.
        let mut entries: Vec<String> = imgs
            .iter()
            .map(|m| format!("{}:{}", m.digest, m.pack_hash.to_hex()))
            .collect();
        entries.sort();
        TestOutcome::pass_with(format!("oci-image-members={}", entries.join(",")))
    }
}

pub struct BundleHasAtLeastOneHelmChartMember;
impl ComplianceTest for BundleHasAtLeastOneHelmChartMember {
    fn id(&self) -> &'static str { "bundle.has_at_least_one_helm_chart_member" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let Some(ms) = members(target) else {
            return TestOutcome::fail("target is not a bundle");
        };
        let charts: Vec<&crate::target::BundleMember> = ms.iter().filter(|m| m.kind == KIND_HELM_CHART).collect();
        if charts.is_empty() {
            return TestOutcome::fail("bundle has no helm-chart members");
        }
        let mut entries: Vec<String> = charts
            .iter()
            .map(|m| format!("{}:{}", m.digest, m.pack_hash.to_hex()))
            .collect();
        entries.sort();
        TestOutcome::pass_with(format!("helm-chart-members={}", entries.join(",")))
    }
}

pub struct BundleMemberDigestsAreDistinct;
impl ComplianceTest for BundleMemberDigestsAreDistinct {
    fn id(&self) -> &'static str { "bundle.member_digests_are_distinct" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let Some(ms) = members(target) else {
            return TestOutcome::fail("target is not a bundle");
        };
        let mut digests: Vec<&String> = ms.iter().map(|m| &m.digest).collect();
        digests.sort();
        let count = digests.len();
        digests.dedup();
        if digests.len() != count {
            return TestOutcome::fail("bundle has duplicate member digests");
        }
        TestOutcome::pass()
    }
}

pub struct BundleAllMemberPackHashesNonZero;
impl ComplianceTest for BundleAllMemberPackHashesNonZero {
    fn id(&self) -> &'static str { "bundle.all_member_pack_hashes_non_zero" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let Some(ms) = members(target) else {
            return TestOutcome::fail("target is not a bundle");
        };
        let zero = [0u8; 32];
        for (i, m) in ms.iter().enumerate() {
            if m.pack_hash.0 == zero {
                return TestOutcome::fail(format!(
                    "member[{i}] (digest={}) has zero pack_hash",
                    m.digest
                ));
            }
        }
        TestOutcome::pass()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::BundleMember;
    use tameshi::hash::Blake3Hash;

    fn good_bundle() -> Target {
        Target::from_bundle_members(vec![
            BundleMember {
                digest: "sha256:aaaa".into(),
                kind: "oci-image".into(),
                pack_hash: Blake3Hash::digest(b"img-pack"),
            },
            BundleMember {
                digest: "sha256:bbbb".into(),
                kind: "helm-chart".into(),
                pack_hash: Blake3Hash::digest(b"chart-pack"),
            },
        ])
    }

    #[test]
    fn good_bundle_passes_all_bundle_tests() {
        assert!(BundleHasAtLeastOneOciImageMember.run(&good_bundle()).is_pass());
        assert!(BundleHasAtLeastOneHelmChartMember.run(&good_bundle()).is_pass());
        assert!(BundleMemberDigestsAreDistinct.run(&good_bundle()).is_pass());
        assert!(BundleAllMemberPackHashesNonZero.run(&good_bundle()).is_pass());
    }

    #[test]
    fn bundle_without_image_fails() {
        let no_image = Target::from_bundle_members(vec![BundleMember {
            digest: "sha256:bbbb".into(),
            kind: "helm-chart".into(),
            pack_hash: Blake3Hash::digest(b"x"),
        }]);
        assert!(matches!(
            BundleHasAtLeastOneOciImageMember.run(&no_image),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn duplicate_digests_fail() {
        let dup = Target::from_bundle_members(vec![
            BundleMember {
                digest: "sha256:same".into(),
                kind: "oci-image".into(),
                pack_hash: Blake3Hash::digest(b"a"),
            },
            BundleMember {
                digest: "sha256:same".into(),
                kind: "helm-chart".into(),
                pack_hash: Blake3Hash::digest(b"b"),
            },
        ]);
        assert!(matches!(
            BundleMemberDigestsAreDistinct.run(&dup),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn zero_pack_hash_fails() {
        let with_zero = Target::from_bundle_members(vec![BundleMember {
            digest: "sha256:aaaa".into(),
            kind: "oci-image".into(),
            pack_hash: Blake3Hash([0u8; 32]),
        }]);
        assert!(matches!(
            BundleAllMemberPackHashesNonZero.run(&with_zero),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn evidence_changes_bundle_pack_hash_when_members_change() {
        // Two bundles, same shape, different image digest. Bundle
        // pack hashes MUST differ — that's how the proof inherits
        // from members.
        use crate::runner::Runner;
        use crate::fedramp_high_openclaw_bundle_v1;
        let pack = fedramp_high_openclaw_bundle_v1();

        let bundle_a = good_bundle();
        let bundle_b = Target::from_bundle_members(vec![
            BundleMember {
                digest: "sha256:DIFFERENT".into(), // changed
                kind: "oci-image".into(),
                pack_hash: Blake3Hash::digest(b"img-pack"),
            },
            BundleMember {
                digest: "sha256:bbbb".into(),
                kind: "helm-chart".into(),
                pack_hash: Blake3Hash::digest(b"chart-pack"),
            },
        ]);
        let r_a = Runner::run_pack(&pack, &bundle_a);
        let r_b = Runner::run_pack(&pack, &bundle_b);
        assert!(r_a.all_passed && r_b.all_passed);
        assert_ne!(
            r_a.pack_hash, r_b.pack_hash,
            "different image member digest MUST yield different bundle pack_hash"
        );
    }
}
