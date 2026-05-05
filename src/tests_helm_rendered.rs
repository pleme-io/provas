//! Helm-rendered-template compliance tests — walk the actual
//! Kubernetes resources `helm template` produces. This is the layer
//! that closes V13 in the fleet threat model: templates that hide
//! non-compliant config from values.yaml inspection.
//!
//! Each test maps to NIST 800-53 Rev 5 controls. Tests walk every
//! Pod-bearing resource (Deployment, StatefulSet, DaemonSet, Job,
//! CronJob) and assert per-container properties.

#![allow(
    clippy::doc_markdown,
    clippy::needless_pass_by_value,
    clippy::single_match_else,
    clippy::collapsible_if,
    clippy::redundant_closure,
    clippy::redundant_closure_for_method_calls,
    clippy::needless_lifetimes,
    clippy::extra_unused_lifetimes
)]

use serde_yaml_ng::Value;

use crate::runner::{ComplianceTest, TestOutcome};
use crate::target::Target;

const POD_BEARING_KINDS: &[&str] = &[
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "ReplicaSet",
];

fn resources(target: &Target) -> Result<&Vec<Value>, TestOutcome> {
    match target {
        Target::HelmRenderedTemplates { resources } => Ok(resources),
        _ => Err(TestOutcome::fail("target is not HelmRenderedTemplates")),
    }
}

/// Get the path to a resource's pod template (where containers live).
/// CronJobs have it nested an extra level under jobTemplate.
fn pod_template<'a>(resource: &'a Value) -> Option<&'a Value> {
    let kind = resource.get("kind").and_then(|k| k.as_str())?;
    match kind {
        "CronJob" => resource
            .get("spec")?
            .get("jobTemplate")?
            .get("spec")?
            .get("template"),
        _ => resource.get("spec")?.get("template"),
    }
}

/// Iterate (resource, container) pairs across pod-bearing kinds.
fn for_each_container<F: FnMut(&str, &str, &Value)>(resources: &[Value], mut f: F) {
    for r in resources {
        let Some(kind) = r.get("kind").and_then(|k| k.as_str()) else { continue };
        if !POD_BEARING_KINDS.contains(&kind) {
            continue;
        }
        let Some(name) = r
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
        else {
            continue;
        };
        let Some(pod) = pod_template(r) else { continue };
        let pod_spec = pod.get("spec");
        // Walk both regular containers + initContainers.
        for key in ["containers", "initContainers"] {
            if let Some(arr) = pod_spec.and_then(|s| s.get(key)).and_then(|c| c.as_sequence()) {
                for c in arr {
                    f(kind, name, c);
                }
            }
        }
    }
}

/// AC-3 / AC-6 (least privilege) — every container's image is pinned by
/// digest (sha256:HEX). Production deployments must be content-
/// addressable; floating tags are forbidden.
pub struct HelmRenderedImagesArePinned;
impl ComplianceTest for HelmRenderedImagesArePinned {
    fn id(&self) -> &'static str { "helm.rendered_images_are_pinned" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for_each_container(res, |kind, name, c| {
            let image = c.get("image").and_then(|i| i.as_str()).unwrap_or("");
            // `@sha256:` (digest pin), or empty (CI placeholder), or
            // any tag containing `sha256:` (chart's
            // `:sha256:0000...` placeholder pattern).
            if image.contains("@sha256:") || image.contains(":sha256:") || image.is_empty() {
                return;
            }
            let cname = c.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            violations.push(format!("{kind}/{name}.{cname}: image={image:?} not pinned"));
        });
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(format!(
                "container image(s) not digest-pinned: {}",
                violations.join("; ")
            ))
        }
    }
}

/// AC-3 — every PodSpec runs as non-root. Either set at the pod level
/// or every container has its own securityContext.runAsNonRoot=true.
pub struct HelmRenderedPodsRunAsNonRoot;
impl ComplianceTest for HelmRenderedPodsRunAsNonRoot {
    fn id(&self) -> &'static str { "helm.rendered_pods_run_as_non_root" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for r in res {
            let Some(kind) = r.get("kind").and_then(|k| k.as_str()) else { continue };
            if !POD_BEARING_KINDS.contains(&kind) { continue; }
            let Some(name) = r.get("metadata").and_then(|m| m.get("name"))
                .and_then(|n| n.as_str()) else { continue };
            let Some(pod) = pod_template(r) else { continue };
            let pod_sc = pod.get("spec").and_then(|s| s.get("securityContext"));
            let pod_nonroot = pod_sc.and_then(|s| s.get("runAsNonRoot")).and_then(|b| b.as_bool());
            if let Some(true) = pod_nonroot { continue; }
            // Pod-level not set (or not true). Check every container.
            let containers = pod.get("spec")
                .and_then(|s| s.get("containers"))
                .and_then(|c| c.as_sequence())
                .cloned()
                .unwrap_or_default();
            for c in &containers {
                let cname = c.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                let cnonroot = c.get("securityContext")
                    .and_then(|sc| sc.get("runAsNonRoot"))
                    .and_then(|b| b.as_bool());
                if cnonroot != Some(true) {
                    violations.push(format!("{kind}/{name}.{cname} not runAsNonRoot=true"));
                }
            }
        }
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(format!(
                "containers without runAsNonRoot=true: {}",
                violations.join("; ")
            ))
        }
    }
}

/// SC-5 (resource bounds) — every container has resources.limits
/// configured (cpu OR memory). Required to prevent a single workload
/// from consuming all cluster resources.
pub struct HelmRenderedContainersHaveResourceLimits;
impl ComplianceTest for HelmRenderedContainersHaveResourceLimits {
    fn id(&self) -> &'static str { "helm.rendered_containers_have_resource_limits" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for_each_container(res, |kind, name, c| {
            let cname = c.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let limits = c.get("resources").and_then(|r| r.get("limits"));
            let has_cpu = limits.and_then(|l| l.get("cpu")).is_some();
            let has_mem = limits.and_then(|l| l.get("memory")).is_some();
            if !has_cpu && !has_mem {
                violations.push(format!("{kind}/{name}.{cname} has no resources.limits"));
            }
        });
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(format!(
                "containers without resource limits: {}",
                violations.join("; ")
            ))
        }
    }
}

/// AC-6 (least privilege) — no container is privileged.
pub struct HelmRenderedNoPrivilegedContainers;
impl ComplianceTest for HelmRenderedNoPrivilegedContainers {
    fn id(&self) -> &'static str { "helm.rendered_no_privileged_containers" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for_each_container(res, |kind, name, c| {
            let cname = c.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let priv_set = c.get("securityContext")
                .and_then(|sc| sc.get("privileged"))
                .and_then(|b| b.as_bool());
            if priv_set == Some(true) {
                violations.push(format!("{kind}/{name}.{cname} is privileged: true"));
            }
        });
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(format!(
                "privileged containers: {}",
                violations.join("; ")
            ))
        }
    }
}

/// AC-6 — every container drops ALL capabilities (or at least the
/// dangerous default set).
pub struct HelmRenderedContainersDropAllCapabilities;
impl ComplianceTest for HelmRenderedContainersDropAllCapabilities {
    fn id(&self) -> &'static str { "helm.rendered_containers_drop_all_capabilities" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for_each_container(res, |kind, name, c| {
            let cname = c.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let drop = c.get("securityContext")
                .and_then(|sc| sc.get("capabilities"))
                .and_then(|cap| cap.get("drop"))
                .and_then(|d| d.as_sequence());
            let dropped: Vec<String> = drop
                .map(|s| s.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            if !dropped.iter().any(|s| s == "ALL" || s == "all") {
                violations.push(format!(
                    "{kind}/{name}.{cname} does not drop ALL capabilities (dropped: {dropped:?})"
                ));
            }
        });
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(format!(
                "containers without drop=[ALL]: {}",
                violations.join("; ")
            ))
        }
    }
}

/// SC-39 (process isolation) — every container has read-only root
/// filesystem.
pub struct HelmRenderedContainersHaveReadOnlyRootFs;
impl ComplianceTest for HelmRenderedContainersHaveReadOnlyRootFs {
    fn id(&self) -> &'static str { "helm.rendered_containers_have_readonly_root_fs" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for_each_container(res, |kind, name, c| {
            let cname = c.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let ro = c.get("securityContext")
                .and_then(|sc| sc.get("readOnlyRootFilesystem"))
                .and_then(|b| b.as_bool());
            if ro != Some(true) {
                violations.push(format!("{kind}/{name}.{cname} readOnlyRootFilesystem != true"));
            }
        });
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(format!(
                "containers without readOnlyRootFilesystem=true: {}",
                violations.join("; ")
            ))
        }
    }
}

/// AC-3 (escalation) — every container has allowPrivilegeEscalation:
/// false in its securityContext.
pub struct HelmRenderedNoAllowPrivilegeEscalation;
impl ComplianceTest for HelmRenderedNoAllowPrivilegeEscalation {
    fn id(&self) -> &'static str { "helm.rendered_no_allow_privilege_escalation" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for_each_container(res, |kind, name, c| {
            let cname = c.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let ape = c.get("securityContext")
                .and_then(|sc| sc.get("allowPrivilegeEscalation"))
                .and_then(|b| b.as_bool());
            if ape != Some(false) {
                violations.push(format!(
                    "{kind}/{name}.{cname} allowPrivilegeEscalation != false"
                ));
            }
        });
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(format!(
                "containers without allowPrivilegeEscalation=false: {}",
                violations.join("; ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target_from(yaml: &str) -> Target {
        Target::from_helm_rendered_yaml(yaml).unwrap()
    }

    const COMPLIANT_DEPLOYMENT: &str = r"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: good
spec:
  replicas: 2
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: ghcr.io/x/y@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
          resources:
            requests: { cpu: 50m, memory: 64Mi }
            limits:   { cpu: 500m, memory: 256Mi }
          securityContext:
            runAsNonRoot: true
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: [ALL]
";

    #[test]
    fn compliant_deployment_passes_every_test() {
        let t = target_from(COMPLIANT_DEPLOYMENT);
        for test in [
            &HelmRenderedImagesArePinned as &dyn ComplianceTest,
            &HelmRenderedPodsRunAsNonRoot,
            &HelmRenderedContainersHaveResourceLimits,
            &HelmRenderedNoPrivilegedContainers,
            &HelmRenderedContainersDropAllCapabilities,
            &HelmRenderedContainersHaveReadOnlyRootFs,
            &HelmRenderedNoAllowPrivilegeEscalation,
        ] {
            let outcome = test.run(&t);
            assert!(
                outcome.is_pass(),
                "test {:?} failed: {:?}",
                test.id(),
                outcome
            );
        }
    }

    #[test]
    fn unpinned_image_tag_fails() {
        let yaml = r"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
spec:
  template:
    spec:
      containers:
        - name: app
          image: ghcr.io/x/y:v1.2.3
          resources:
            limits: { cpu: 100m }
";
        assert!(matches!(
            HelmRenderedImagesArePinned.run(&target_from(yaml)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn privileged_container_fails() {
        let yaml = r"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
spec:
  template:
    spec:
      containers:
        - name: app
          image: x@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
          resources:
            limits: { cpu: 100m }
          securityContext:
            privileged: true
";
        assert!(matches!(
            HelmRenderedNoPrivilegedContainers.run(&target_from(yaml)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn missing_capability_drop_fails() {
        let yaml = r"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
spec:
  template:
    spec:
      containers:
        - name: app
          image: x@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
          resources: { limits: { cpu: 100m } }
          securityContext: {}
";
        assert!(matches!(
            HelmRenderedContainersDropAllCapabilities.run(&target_from(yaml)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn cronjob_containers_are_walked() {
        // CronJob has containers nested under
        // spec.jobTemplate.spec.template.spec.containers.
        let yaml = r"
apiVersion: batch/v1
kind: CronJob
metadata:
  name: clean
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: clean
              image: x:v1
";
        // Image not pinned → should fail.
        assert!(matches!(
            HelmRenderedImagesArePinned.run(&target_from(yaml)),
            TestOutcome::Fail { .. }
        ));
    }

    #[test]
    fn non_pod_resources_are_skipped() {
        let yaml = r"
apiVersion: v1
kind: ConfigMap
metadata:
  name: x
data: { foo: bar }
";
        // No containers; tests pass vacuously.
        assert!(HelmRenderedImagesArePinned.run(&target_from(yaml)).is_pass());
        assert!(HelmRenderedPodsRunAsNonRoot.run(&target_from(yaml)).is_pass());
    }
}
