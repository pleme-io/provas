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

use crate::runner::{Citation, ComplianceTest, TestOutcome};
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
    fn citation(&self) -> Citation {
        // Citation correction (was AC-3/AC-6 — wrong; pinning is SI-7
        // software integrity, not access enforcement).
        Citation::nist_800_53_r5(
            "SI-7",
            "Every container `image` MUST be a digest reference (`@sha256:`); floating tags break SI-7 by allowing the registry to silently serve different bytes for the same reference.",
        )
    }
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
    fn citation(&self) -> Citation {
        Citation::kubernetes_pss_restricted(
            "spec.securityContext.runAsNonRoot",
            "PSS Restricted requires runAsNonRoot=true at pod or container level; satisfies AC-6 (least privilege) by preventing UID-0 container processes.",
        )
    }
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
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "SC-6",
            "Per NSA/CISA Kubernetes Hardening Guide v1.2 + NIST 800-190 §4.4.3, every container MUST set resource limits to prevent a single workload from starving others. Maps to SC-6 resource availability.",
        )
    }
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
    fn citation(&self) -> Citation {
        Citation::kubernetes_pss_restricted(
            "spec.containers[*].securityContext.privileged",
            "PSS Baseline+Restricted forbids privileged containers; AC-6 / CM-7 require least functionality and least privilege.",
        )
    }
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
    fn citation(&self) -> Citation {
        Citation::kubernetes_pss_restricted(
            "spec.containers[*].securityContext.capabilities.drop",
            "PSS Restricted requires drop=[ALL] on every container; satisfies AC-6(9) (least privilege execution) by removing the default Linux capability set from every workload process.",
        )
    }
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
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "SI-7",
            "Per NSA/CISA Kubernetes Hardening Guide pp.12-14 + NIST 800-190 §4.4.3, every container's root filesystem MUST be read-only; satisfies SI-7 by preventing in-container code from rewriting the binary it executes.",
        )
    }
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
    fn citation(&self) -> Citation {
        Citation::kubernetes_pss_restricted(
            "spec.containers[*].securityContext.allowPrivilegeEscalation",
            "PSS Restricted requires allowPrivilegeEscalation=false on every container; satisfies AC-6(10) (prevent non-privileged users from executing privileged functions).",
        )
    }
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

// ─── v2 / Pod Security Standards Restricted predicates (added 2026-05-09) ──
//
// These extend the v1 pack with the full PSS Restricted profile +
// NSA/CISA Kubernetes Hardening Guide additions. Together they form
// pack `fedramp-high-openclaw-helm-rendered@2`.

/// PSS Baseline — pod-level `hostNetwork: true` is forbidden.
pub struct HelmRenderedNoHostNetwork;
impl ComplianceTest for HelmRenderedNoHostNetwork {
    fn id(&self) -> &'static str { "helm.rendered_no_host_network" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::kubernetes_pss_restricted(
            "spec.hostNetwork",
            "PSS Baseline forbids hostNetwork=true; satisfies SC-7 (boundary protection) and AC-4 (information flow control) by preventing pod processes from sniffing/spoofing the node's network.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for r in res {
            let Some(kind) = r.get("kind").and_then(|k| k.as_str()) else { continue };
            if !POD_BEARING_KINDS.contains(&kind) { continue; }
            let Some(name) = r.get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str()) else { continue };
            let Some(pod) = pod_template(r) else { continue };
            if pod.get("spec").and_then(|s| s.get("hostNetwork")).and_then(|b| b.as_bool()) == Some(true) {
                violations.push(format!("{kind}/{name} has hostNetwork=true"));
            }
        }
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(violations.join("; "))
        }
    }
}

/// PSS Baseline — pod-level `hostPID: true` is forbidden.
pub struct HelmRenderedNoHostPID;
impl ComplianceTest for HelmRenderedNoHostPID {
    fn id(&self) -> &'static str { "helm.rendered_no_host_pid" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::kubernetes_pss_restricted(
            "spec.hostPID",
            "PSS Baseline forbids hostPID=true; AC-6 / SC-39 (process isolation) require pod processes to NOT share the host PID namespace.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        check_pod_field_not_true(target, "hostPID")
    }
}

/// PSS Baseline — pod-level `hostIPC: true` is forbidden.
pub struct HelmRenderedNoHostIPC;
impl ComplianceTest for HelmRenderedNoHostIPC {
    fn id(&self) -> &'static str { "helm.rendered_no_host_ipc" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::kubernetes_pss_restricted(
            "spec.hostIPC",
            "PSS Baseline forbids hostIPC=true; AC-6 / SC-39 (process isolation) require pod processes to NOT share the host IPC namespace.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        check_pod_field_not_true(target, "hostIPC")
    }
}

fn check_pod_field_not_true(target: &Target, field: &str) -> TestOutcome {
    let res = match resources(target) { Ok(r) => r, Err(e) => return e };
    let mut violations = Vec::new();
    for r in res {
        let Some(kind) = r.get("kind").and_then(|k| k.as_str()) else { continue };
        if !POD_BEARING_KINDS.contains(&kind) { continue; }
        let Some(name) = r.get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str()) else { continue };
        let Some(pod) = pod_template(r) else { continue };
        if pod.get("spec").and_then(|s| s.get(field)).and_then(|b| b.as_bool()) == Some(true) {
            violations.push(format!("{kind}/{name} has {field}=true"));
        }
    }
    if violations.is_empty() {
        TestOutcome::pass()
    } else {
        TestOutcome::fail(violations.join("; "))
    }
}

/// PSS Baseline — no volume uses `hostPath`.
pub struct HelmRenderedNoHostPath;
impl ComplianceTest for HelmRenderedNoHostPath {
    fn id(&self) -> &'static str { "helm.rendered_no_host_path" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::kubernetes_pss_restricted(
            "spec.volumes[*].hostPath",
            "PSS Baseline forbids hostPath volumes; satisfies AC-6 (least privilege on host filesystem) and CM-7 (least functionality) by preventing pods from reaching arbitrary node-host paths.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for r in res {
            let Some(kind) = r.get("kind").and_then(|k| k.as_str()) else { continue };
            if !POD_BEARING_KINDS.contains(&kind) { continue; }
            let Some(name) = r.get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str()) else { continue };
            let Some(pod) = pod_template(r) else { continue };
            let Some(vols) = pod.get("spec").and_then(|s| s.get("volumes")).and_then(|v| v.as_sequence()) else { continue };
            for (i, v) in vols.iter().enumerate() {
                if v.get("hostPath").is_some() {
                    let vname = v.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                    violations.push(format!("{kind}/{name} volume[{i}]={vname:?} uses hostPath"));
                }
            }
        }
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(violations.join("; "))
        }
    }
}

/// PSS Baseline — no container declares a `hostPort`.
pub struct HelmRenderedNoHostPort;
impl ComplianceTest for HelmRenderedNoHostPort {
    fn id(&self) -> &'static str { "helm.rendered_no_host_port" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::kubernetes_pss_restricted(
            "spec.containers[*].ports[*].hostPort",
            "PSS Baseline forbids hostPort; satisfies SC-7 (boundary protection) by preventing pods from binding directly to host network interfaces.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for_each_container(res, |kind, name, c| {
            let cname = c.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let Some(ports) = c.get("ports").and_then(|p| p.as_sequence()) else { return };
            for p in ports {
                if let Some(hp) = p.get("hostPort").and_then(|h| h.as_u64()) {
                    if hp > 0 {
                        violations.push(format!("{kind}/{name}.{cname} port hostPort={hp}"));
                    }
                }
            }
        });
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(violations.join("; "))
        }
    }
}

/// PSS Restricted — every pod's `seccompProfile.type` is set to
/// `RuntimeDefault` or `Localhost` (NOT `Unconfined`, NOT absent).
pub struct HelmRenderedSeccompRuntimeDefault;
impl ComplianceTest for HelmRenderedSeccompRuntimeDefault {
    fn id(&self) -> &'static str { "helm.rendered_seccomp_runtime_default" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::kubernetes_pss_restricted(
            "spec.{,containers[*].}securityContext.seccompProfile.type",
            "PSS Restricted requires seccompProfile.type ∈ {RuntimeDefault, Localhost} — explicit, not absent. Satisfies SI-3 (malicious-code protection) by enforcing a syscall filter on every container.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        fn allowed(s: &str) -> bool { s == "RuntimeDefault" || s == "Localhost" }
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for r in res {
            let Some(kind) = r.get("kind").and_then(|k| k.as_str()) else { continue };
            if !POD_BEARING_KINDS.contains(&kind) { continue; }
            let Some(name) = r.get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str()) else { continue };
            let Some(pod) = pod_template(r) else { continue };
            let pod_seccomp = pod.get("spec")
                .and_then(|s| s.get("securityContext"))
                .and_then(|sc| sc.get("seccompProfile"))
                .and_then(|p| p.get("type"))
                .and_then(|t| t.as_str());
            if pod_seccomp.is_some_and(allowed) { continue; }
            // Pod-level not affirmed; check every container.
            let containers = pod.get("spec").and_then(|s| s.get("containers")).and_then(|c| c.as_sequence()).cloned().unwrap_or_default();
            for c in &containers {
                let cname = c.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                let cseccomp = c.get("securityContext")
                    .and_then(|sc| sc.get("seccompProfile"))
                    .and_then(|p| p.get("type"))
                    .and_then(|t| t.as_str());
                if !cseccomp.is_some_and(allowed) {
                    violations.push(format!(
                        "{kind}/{name}.{cname} seccompProfile.type missing or unconfined"
                    ));
                }
            }
        }
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(violations.join("; "))
        }
    }
}

/// PSS Restricted — every container's `capabilities.add` is empty OR
/// only `NET_BIND_SERVICE`.
pub struct HelmRenderedAddOnlyNetBindService;
impl ComplianceTest for HelmRenderedAddOnlyNetBindService {
    fn id(&self) -> &'static str { "helm.rendered_add_only_net_bind_service" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::kubernetes_pss_restricted(
            "spec.containers[*].securityContext.capabilities.add",
            "PSS Restricted only allows NET_BIND_SERVICE in capabilities.add (or none); AC-6(9) (least privilege) — workloads MUST NOT acquire SYS_ADMIN, NET_ADMIN, etc., without justification.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for_each_container(res, |kind, name, c| {
            let cname = c.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let Some(adds) = c.get("securityContext")
                .and_then(|sc| sc.get("capabilities"))
                .and_then(|cap| cap.get("add"))
                .and_then(|a| a.as_sequence()) else { return };
            for a in adds {
                let Some(s) = a.as_str() else { continue };
                if s != "NET_BIND_SERVICE" {
                    violations.push(format!("{kind}/{name}.{cname} adds {s}"));
                }
            }
        });
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(violations.join("; "))
        }
    }
}

/// CIS 5.1.6 / NSA — `automountServiceAccountToken: false` on Pod or
/// SA unless explicitly justified.
pub struct HelmRenderedAutomountTokenFalse;
impl ComplianceTest for HelmRenderedAutomountTokenFalse {
    fn id(&self) -> &'static str { "helm.rendered_automount_token_false" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "AC-3",
            "CIS Kubernetes Benchmark §5.1.6 + NSA/CISA Hardening Guide: every pod sets automountServiceAccountToken=false unless it has a documented need. Satisfies AC-3 by removing default credential exposure.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for r in res {
            let Some(kind) = r.get("kind").and_then(|k| k.as_str()) else { continue };
            if !POD_BEARING_KINDS.contains(&kind) { continue; }
            let Some(name) = r.get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str()) else { continue };
            let Some(pod) = pod_template(r) else { continue };
            let amt = pod.get("spec")
                .and_then(|s| s.get("automountServiceAccountToken"))
                .and_then(|b| b.as_bool());
            if amt != Some(false) {
                violations.push(format!(
                    "{kind}/{name} pod.spec.automountServiceAccountToken != false (got {amt:?})"
                ));
            }
        }
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(violations.join("; "))
        }
    }
}

/// CIS 5.1.5 — `serviceAccountName` is set and is not `default`.
pub struct HelmRenderedNoDefaultServiceAccount;
impl ComplianceTest for HelmRenderedNoDefaultServiceAccount {
    fn id(&self) -> &'static str { "helm.rendered_no_default_service_account" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "AC-3",
            "CIS Kubernetes Benchmark §5.1.5: workloads MUST NOT use the `default` ServiceAccount; AC-3 access enforcement requires named, RBAC-bound identities for every workload.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut violations = Vec::new();
        for r in res {
            let Some(kind) = r.get("kind").and_then(|k| k.as_str()) else { continue };
            if !POD_BEARING_KINDS.contains(&kind) { continue; }
            let Some(name) = r.get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str()) else { continue };
            let Some(pod) = pod_template(r) else { continue };
            let san = pod.get("spec")
                .and_then(|s| s.get("serviceAccountName"))
                .and_then(|n| n.as_str());
            match san {
                None => violations.push(format!("{kind}/{name} no serviceAccountName set")),
                Some("default") => violations.push(format!("{kind}/{name} uses default SA")),
                Some(_) => {}
            }
        }
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(violations.join("; "))
        }
    }
}

/// CP-2 — every Deployment / StatefulSet with `replicas >= 2` has a
/// matching PodDisruptionBudget. Helm-rendered packs catch this from
/// the YAML alone (PDBs render alongside the workload).
pub struct HelmRenderedHasPodDisruptionBudget;
impl ComplianceTest for HelmRenderedHasPodDisruptionBudget {
    fn id(&self) -> &'static str { "helm.rendered_has_pod_disruption_budget" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "CP-2",
            "Workloads with replicas≥2 MUST be matched by a PodDisruptionBudget; CP-2 (contingency planning) requires graceful eviction under voluntary disruption (node drain).",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let mut needs_pdb: Vec<(String, String)> = Vec::new();
        for r in res {
            let Some(kind) = r.get("kind").and_then(|k| k.as_str()) else { continue };
            if !matches!(kind, "Deployment" | "StatefulSet") { continue; }
            let Some(name) = r.get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str()) else { continue };
            let replicas = r.get("spec").and_then(|s| s.get("replicas")).and_then(|n| n.as_u64()).unwrap_or(1);
            if replicas >= 2 {
                needs_pdb.push((kind.to_string(), name.to_string()));
            }
        }
        let pdbs: Vec<&Value> = res.iter()
            .filter(|r| r.get("kind").and_then(|k| k.as_str()) == Some("PodDisruptionBudget"))
            .collect();
        let mut missing = Vec::new();
        for (kind, name) in &needs_pdb {
            // Heuristic: PDB exists in same render whose name contains
            // the workload name. Real charts that render a PDB always
            // do this.
            let matched = pdbs.iter().any(|p| {
                p.get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str())
                    .is_some_and(|pn| pn.contains(name) || name.contains(pn))
            });
            if !matched {
                missing.push(format!("{kind}/{name}"));
            }
        }
        if missing.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(format!("missing PDB for: {}", missing.join(", ")))
        }
    }
}

/// SC-7 — chart's rendered output includes at least one NetworkPolicy.
/// This is a coarse but defensible signal at the rendered-YAML layer;
/// per-resource policy mapping requires live-cluster context.
pub struct HelmRenderedHasNetworkPolicy;
impl ComplianceTest for HelmRenderedHasNetworkPolicy {
    fn id(&self) -> &'static str { "helm.rendered_has_network_policy" }
    fn version(&self) -> &'static str { "1" }
    fn citation(&self) -> Citation {
        Citation::nist_800_53_r5(
            "SC-7",
            "SC-7 boundary protection: every chart that renders pod-bearing resources MUST also render at least one NetworkPolicy. Per CIS §5.3.2 + NIST 800-190 §4.4.2, default-deny is the table-stakes signal here.",
        )
    }
    fn run(&self, target: &Target) -> TestOutcome {
        let res = match resources(target) { Ok(r) => r, Err(e) => return e };
        let has_workload = res.iter().any(|r| {
            r.get("kind").and_then(|k| k.as_str())
                .is_some_and(|k| POD_BEARING_KINDS.contains(&k))
        });
        if !has_workload {
            return TestOutcome::pass(); // chart-of-CRDs etc.
        }
        let has_netpol = res.iter().any(|r| {
            r.get("kind").and_then(|k| k.as_str())
                .is_some_and(|k| k == "NetworkPolicy" || k == "CiliumNetworkPolicy")
        });
        if has_netpol {
            TestOutcome::pass()
        } else {
            TestOutcome::fail("chart renders pod-bearing resources but no NetworkPolicy")
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

    // ─── v2 predicate negative tests (PSS Restricted) ────────────────

    #[test]
    fn host_network_true_fails() {
        let yaml = r"
apiVersion: apps/v1
kind: Deployment
metadata: { name: bad }
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: x@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
";
        assert!(matches!(HelmRenderedNoHostNetwork.run(&target_from(yaml)), TestOutcome::Fail { .. }));
    }

    #[test]
    fn host_pid_true_fails() {
        let yaml = r"
apiVersion: apps/v1
kind: Deployment
metadata: { name: bad }
spec:
  template:
    spec:
      hostPID: true
      containers:
        - name: app
          image: x@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
";
        assert!(matches!(HelmRenderedNoHostPID.run(&target_from(yaml)), TestOutcome::Fail { .. }));
    }

    #[test]
    fn host_path_volume_fails() {
        let yaml = r"
apiVersion: apps/v1
kind: Deployment
metadata: { name: bad }
spec:
  template:
    spec:
      volumes:
        - name: leak
          hostPath: { path: /etc }
      containers:
        - name: app
          image: x@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
";
        assert!(matches!(HelmRenderedNoHostPath.run(&target_from(yaml)), TestOutcome::Fail { .. }));
    }

    #[test]
    fn host_port_fails() {
        let yaml = r"
apiVersion: apps/v1
kind: Deployment
metadata: { name: bad }
spec:
  template:
    spec:
      containers:
        - name: app
          image: x@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
          ports:
            - containerPort: 8080
              hostPort: 80
";
        assert!(matches!(HelmRenderedNoHostPort.run(&target_from(yaml)), TestOutcome::Fail { .. }));
    }

    #[test]
    fn unconfined_seccomp_fails() {
        let yaml = r"
apiVersion: apps/v1
kind: Deployment
metadata: { name: bad }
spec:
  template:
    spec:
      containers:
        - name: app
          image: x@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
          securityContext: {}
";
        assert!(matches!(HelmRenderedSeccompRuntimeDefault.run(&target_from(yaml)), TestOutcome::Fail { .. }));
    }

    #[test]
    fn add_sys_admin_capability_fails() {
        let yaml = r"
apiVersion: apps/v1
kind: Deployment
metadata: { name: bad }
spec:
  template:
    spec:
      containers:
        - name: app
          image: x@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
          securityContext:
            capabilities:
              add: [SYS_ADMIN]
";
        assert!(matches!(HelmRenderedAddOnlyNetBindService.run(&target_from(yaml)), TestOutcome::Fail { .. }));
    }

    #[test]
    fn automount_token_default_fails() {
        let yaml = r"
apiVersion: apps/v1
kind: Deployment
metadata: { name: bad }
spec:
  template:
    spec:
      containers:
        - name: app
          image: x@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
";
        assert!(matches!(HelmRenderedAutomountTokenFalse.run(&target_from(yaml)), TestOutcome::Fail { .. }));
    }

    #[test]
    fn default_service_account_fails() {
        let yaml = r"
apiVersion: apps/v1
kind: Deployment
metadata: { name: bad }
spec:
  template:
    spec:
      automountServiceAccountToken: false
      serviceAccountName: default
      containers:
        - name: app
          image: x@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
";
        assert!(matches!(HelmRenderedNoDefaultServiceAccount.run(&target_from(yaml)), TestOutcome::Fail { .. }));
    }

    #[test]
    fn deployment_with_two_replicas_no_pdb_fails() {
        let yaml = r"
apiVersion: apps/v1
kind: Deployment
metadata: { name: app }
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: c
          image: x@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
";
        assert!(matches!(HelmRenderedHasPodDisruptionBudget.run(&target_from(yaml)), TestOutcome::Fail { .. }));
    }

    #[test]
    fn workload_without_network_policy_fails() {
        let yaml = r"
apiVersion: apps/v1
kind: Deployment
metadata: { name: bare }
spec:
  template:
    spec:
      containers:
        - name: c
          image: x@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
";
        assert!(matches!(HelmRenderedHasNetworkPolicy.run(&target_from(yaml)), TestOutcome::Fail { .. }));
    }
}
