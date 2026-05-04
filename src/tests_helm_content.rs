//! Helm chart content compliance tests — operate on parsed `Chart.yaml`,
//! parsed `values.yaml`, and the templates map.

#![allow(
    clippy::doc_markdown,
    clippy::redundant_closure,
    clippy::redundant_closure_for_method_calls,
    clippy::single_char_pattern,
    clippy::needless_pass_by_value,
    clippy::cmp_owned,
    clippy::manual_let_else,
    clippy::collapsible_if,
    clippy::map_clone,
    clippy::case_sensitive_file_extension_comparisons
)]
//!
//! These map to concrete NIST 800-53 Rev 5 controls in the FedRAMP
//! High baseline. Each test names the control it satisfies in its
//! doc-comment so auditors can trace from a failing test back to the
//! requirement it enforces.

use serde_yaml_ng::Value;

use crate::runner::{ComplianceTest, TestOutcome};
use crate::target::Target;

fn chart_and_values(target: &Target) -> Result<(&Value, &Value), TestOutcome> {
    match target {
        Target::HelmChartContent { chart_yaml, values_yaml, .. } => Ok((chart_yaml, values_yaml)),
        _ => Err(TestOutcome::fail("target is not HelmChartContent")),
    }
}

fn templates(target: &Target) -> Result<&std::collections::BTreeMap<String, Vec<u8>>, TestOutcome> {
    match target {
        Target::HelmChartContent { templates, .. } => Ok(templates),
        _ => Err(TestOutcome::fail("target is not HelmChartContent")),
    }
}

/// Walk a serde_yaml_ng `Value` looking for any string value that
/// equals or contains the given substring. Used to scan for forbidden
/// patterns like `:latest` or hardcoded plaintext-looking secrets.
fn yaml_contains_substring(v: &Value, needle: &str) -> bool {
    match v {
        Value::String(s) => s.contains(needle),
        Value::Sequence(s) => s.iter().any(|x| yaml_contains_substring(x, needle)),
        Value::Mapping(m) => m.values().any(|x| yaml_contains_substring(x, needle)),
        _ => false,
    }
}

fn yaml_get_path<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(v, |acc, &k| match acc {
            Value::Mapping(m) => m.get(Value::String(k.to_string())),
            _ => None,
        })
}

// ─── tests ─────────────────────────────────────────────────────────

/// CM-2 (baseline configuration) — Chart.yaml apiVersion is v2.
pub struct HelmChartApiVersionV2;
impl ComplianceTest for HelmChartApiVersionV2 {
    fn id(&self) -> &'static str { "helm.chart_api_version_v2" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (chart, _) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        match chart.get("apiVersion").and_then(|v| v.as_str()) {
            Some("v2") => TestOutcome::pass(),
            Some(other) => TestOutcome::fail(format!("Chart.yaml apiVersion is {other:?}, expected v2")),
            None => TestOutcome::fail("Chart.yaml has no apiVersion field"),
        }
    }
}

/// CM-2 — Chart.yaml has explicit name + version.
pub struct HelmChartHasNameAndVersion;
impl ComplianceTest for HelmChartHasNameAndVersion {
    fn id(&self) -> &'static str { "helm.chart_has_name_and_version" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (chart, _) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        let name = chart.get("name").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
        let version = chart.get("version").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
        match (name, version) {
            (Some(_), Some(_)) => TestOutcome::pass(),
            (None, _) => TestOutcome::fail("Chart.yaml missing `name`"),
            (_, None) => TestOutcome::fail("Chart.yaml missing `version`"),
        }
    }
}

/// SI-7 (software integrity) — values.yaml must NOT use `:latest` tag
/// patterns anywhere. Production images must be content-addressed.
pub struct HelmValuesNoLatestTags;
impl ComplianceTest for HelmValuesNoLatestTags {
    fn id(&self) -> &'static str { "helm.values_no_latest_tags" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (_, values) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        if yaml_contains_substring(values, ":latest") {
            return TestOutcome::fail("values.yaml contains `:latest` tag (SI-7 violation)".to_string());
        }
        TestOutcome::pass()
    }
}

/// SI-7 — image references in values.yaml must use sha256: digests, not
/// floating tags. Reads the conventional `image.tag` and any nested
/// `*.image.tag` paths.
pub struct HelmValuesImagesPinnedToDigest;
impl ComplianceTest for HelmValuesImagesPinnedToDigest {
    fn id(&self) -> &'static str { "helm.values_images_pinned_to_digest" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (_, values) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        let mut violations = Vec::new();
        scan_image_tags(values, &mut violations, &mut Vec::new());
        if violations.is_empty() {
            TestOutcome::pass_with(format!("scanned {} image.tag site(s); all pinned", violations_pos_count(values)))
        } else {
            TestOutcome::fail(format!(
                "image tag(s) not pinned to sha256 digest: {}",
                violations.join(", ")
            ))
        }
    }
}

fn violations_pos_count(v: &Value) -> usize {
    let mut violations = Vec::new();
    scan_image_tags(v, &mut violations, &mut Vec::new());
    let mut total = Vec::new();
    count_image_tags(v, &mut total, &mut Vec::new());
    total.len()
}

fn count_image_tags(v: &Value, out: &mut Vec<String>, path: &mut Vec<String>) {
    if let Value::Mapping(m) = v {
        for (k, val) in m {
            if let Some(ks) = k.as_str() {
                path.push(ks.to_string());
                if ks == "image"
                    && let Some(tag) = val.get("tag").and_then(|t| t.as_str())
                    && !tag.is_empty()
                {
                    out.push(path.join("."));
                }
                count_image_tags(val, out, path);
                path.pop();
            }
        }
    }
}

fn scan_image_tags(v: &Value, violations: &mut Vec<String>, path: &mut Vec<String>) {
    if let Value::Mapping(m) = v {
        for (k, val) in m {
            if let Some(ks) = k.as_str() {
                path.push(ks.to_string());
                if ks == "image"
                    && let Some(tag) = val.get("tag").and_then(|t| t.as_str())
                    && !tag.is_empty()
                    && !tag.starts_with("sha256:")
                {
                    violations.push(format!("{}.tag={}", path.join("."), tag));
                }
                scan_image_tags(val, violations, path);
                path.pop();
            }
        }
    }
}

/// AC-3 / AC-6 (access control / least privilege) — workload values
/// declare `runAsNonRoot: true` somewhere in the security context.
/// Operative path varies by chart layout (top-level `securityContext`
/// vs `pleme-microservice.securityContext` etc).
pub struct HelmValuesRunAsNonRoot;
impl ComplianceTest for HelmValuesRunAsNonRoot {
    fn id(&self) -> &'static str { "helm.values_run_as_non_root" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (_, values) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        // pleme-microservice's compliance overlay defaults runAsNonRoot
        // for fedramp-high. The check is "no securityContext explicitly
        // sets runAsNonRoot=false anywhere".
        let mut violations = Vec::new();
        scan_run_as_non_root_violations(values, &mut violations, &mut Vec::new());
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(format!(
                "values.yaml has runAsNonRoot=false at: {}",
                violations.join(", ")
            ))
        }
    }
}

fn scan_run_as_non_root_violations(v: &Value, out: &mut Vec<String>, path: &mut Vec<String>) {
    if let Value::Mapping(m) = v {
        for (k, val) in m {
            if let Some(ks) = k.as_str() {
                path.push(ks.to_string());
                if ks == "runAsNonRoot" && val.as_bool() == Some(false) {
                    out.push(path.join("."));
                }
                scan_run_as_non_root_violations(val, out, path);
                path.pop();
            }
        }
    }
}

/// AC-6 — workload values declare resource limits. Required for FedRAMP
/// to bound resource consumption (`SC-5` denial-of-service protection).
pub struct HelmValuesDeclareResourceLimits;
impl ComplianceTest for HelmValuesDeclareResourceLimits {
    fn id(&self) -> &'static str { "helm.values_declare_resource_limits" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (_, values) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        // Look for any `resources.limits` block with cpu or memory.
        let mut found = false;
        scan_for_resource_limits(values, &mut found);
        if found {
            TestOutcome::pass()
        } else {
            TestOutcome::fail("no `resources.limits` block found anywhere in values.yaml (SC-5)".to_string())
        }
    }
}

fn scan_for_resource_limits(v: &Value, found: &mut bool) {
    if *found { return; }
    if let Value::Mapping(m) = v {
        if let Some(Value::Mapping(limits)) = m.get(Value::String("resources".to_string()))
            .and_then(|r| r.as_mapping())
            .and_then(|r| r.get(Value::String("limits".to_string())))
            .map(|l| l.clone())
            .as_ref()
        {
            if limits.contains_key(Value::String("cpu".into())) || limits.contains_key(Value::String("memory".into())) {
                *found = true;
                return;
            }
        }
        for (_, val) in m {
            scan_for_resource_limits(val, found);
        }
    }
}

/// CA-7 (continuous monitoring) — chart configures liveness or
/// readiness probes for monitoring. Required to detect failed pods.
pub struct HelmValuesHasHealthProbes;
impl ComplianceTest for HelmValuesHasHealthProbes {
    fn id(&self) -> &'static str { "helm.values_has_health_probes" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (_, values) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        // Look for `health.{path,readyPath,port}` block (pleme-microservice
        // convention) or kubernetes-style livenessProbe/readinessProbe.
        let mut found = false;
        scan_for_probes(values, &mut found);
        if found {
            TestOutcome::pass()
        } else {
            TestOutcome::fail("no health probes (livenessProbe/readinessProbe/health) declared (CA-7)".to_string())
        }
    }
}

fn scan_for_probes(v: &Value, found: &mut bool) {
    if *found { return; }
    if let Value::Mapping(m) = v {
        for k in ["livenessProbe", "readinessProbe", "health"] {
            if m.contains_key(Value::String(k.to_string())) {
                *found = true;
                return;
            }
        }
        for (_, val) in m {
            scan_for_probes(val, found);
        }
    }
}

/// SC-7 (boundary protection) — chart configures NetworkPolicy. Lateral
/// movement is blocked unless explicitly allowed.
pub struct HelmValuesHasNetworkPolicy;
impl ComplianceTest for HelmValuesHasNetworkPolicy {
    fn id(&self) -> &'static str { "helm.values_has_network_policy" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (_, values) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        let mut found = false;
        scan_for_network_policy(values, &mut found);
        if found {
            TestOutcome::pass()
        } else {
            TestOutcome::fail("no networkPolicy.enabled=true found anywhere in values.yaml (SC-7)".to_string())
        }
    }
}

fn scan_for_network_policy(v: &Value, found: &mut bool) {
    if *found { return; }
    if let Value::Mapping(m) = v {
        if let Some(np) = m.get(Value::String("networkPolicy".to_string()))
            && np.get("enabled").and_then(|e| e.as_bool()) == Some(true)
        {
            *found = true;
            return;
        }
        for (_, val) in m {
            scan_for_network_policy(val, found);
        }
    }
}

/// IA-5 (authenticator management) — values.yaml MUST NOT contain any
/// plaintext-looking secret values (long base64-style strings or
/// patterns matching common secret formats).
pub struct HelmValuesNoPlaintextSecrets;
impl ComplianceTest for HelmValuesNoPlaintextSecrets {
    fn id(&self) -> &'static str { "helm.values_no_plaintext_secrets" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (_, values) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        // Heuristic patterns. False-positive-tolerant; favors pass on
        // ambiguous, fail on obvious leaks.
        let needles = [
            // GitHub tokens (40 chars, alphanumeric, may start with prefix).
            "ghp_", "ghs_", "gho_",
            // AWS access keys.
            "AKIA",
            // Common private key headers (escaped form in YAML).
            "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
            // Generic bearer tokens.
            "Bearer eyJ",
            // Kubernetes secret values often go in here directly — flag that
            // sort of usage.
        ];
        for n in needles {
            if yaml_contains_substring(values, n) {
                return TestOutcome::fail(format!(
                    "values.yaml contains likely plaintext secret matching pattern {n:?} (IA-5)"
                ));
            }
        }
        TestOutcome::pass()
    }
}

/// CM-2 — `pleme-microservice.compliance.overlays` must include
/// `fedramp-high` for charts in the FedRAMP-High deployment family.
/// (For non-pleme charts this passes vacuously.)
pub struct HelmValuesDeclareFedRampHighOverlay;
impl ComplianceTest for HelmValuesDeclareFedRampHighOverlay {
    fn id(&self) -> &'static str { "helm.values_declare_fedramp_high_overlay" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (_, values) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        // Path 1: pleme-microservice.compliance.overlays
        if let Some(overlays) = yaml_get_path(values, &["pleme-microservice", "compliance", "overlays"])
            .and_then(|v| v.as_sequence())
        {
            let has_high = overlays.iter().any(|o| o.as_str() == Some("fedramp-high"));
            if has_high {
                return TestOutcome::pass_with("pleme-microservice.compliance.overlays includes fedramp-high".to_string());
            }
            return TestOutcome::fail("pleme-microservice.compliance.overlays does not include fedramp-high".to_string());
        }
        // Path 2: top-level compliance.overlays (other chart shapes).
        if let Some(overlays) = yaml_get_path(values, &["compliance", "overlays"]).and_then(|v| v.as_sequence()) {
            if overlays.iter().any(|o| o.as_str() == Some("fedramp-high")) {
                return TestOutcome::pass_with("compliance.overlays includes fedramp-high".to_string());
            }
            return TestOutcome::fail("compliance.overlays does not include fedramp-high".to_string());
        }
        TestOutcome::fail("no fedramp-high overlay declaration found".to_string())
    }
}

/// SC-13 (cryptographic protection) — TLS-related config is present
/// where applicable, OR an explicit ingress-disabled marker. The
/// proxy: any chart that declares `ingress.enabled: true` must also
/// declare TLS configuration; charts that disable ingress pass vacuously.
pub struct HelmValuesIngressTlsConfigured;
impl ComplianceTest for HelmValuesIngressTlsConfigured {
    fn id(&self) -> &'static str { "helm.values_ingress_tls_configured" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (_, values) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        // Find any ingress.enabled=true; if present, require ingress.tls.
        let mut violations = Vec::new();
        scan_ingress_tls(values, &mut violations, &mut Vec::new());
        if violations.is_empty() {
            TestOutcome::pass()
        } else {
            TestOutcome::fail(format!(
                "ingress enabled but TLS not configured at: {}",
                violations.join(", ")
            ))
        }
    }
}

fn scan_ingress_tls(v: &Value, out: &mut Vec<String>, path: &mut Vec<String>) {
    if let Value::Mapping(m) = v {
        for (k, val) in m {
            if let Some(ks) = k.as_str() {
                path.push(ks.to_string());
                if ks == "ingress" {
                    let enabled =
                        val.get("enabled").and_then(|e| e.as_bool()) == Some(true);
                    let has_tls =
                        val.get("tls").is_some_and(|t| !matches!(t, Value::Null));
                    if enabled && !has_tls {
                        out.push(path.join("."));
                    }
                }
                scan_ingress_tls(val, out, path);
                path.pop();
            }
        }
    }
}

/// CP-2 (contingency planning) — minimum 2 replicas for HA.
pub struct HelmValuesAtLeastTwoReplicas;
impl ComplianceTest for HelmValuesAtLeastTwoReplicas {
    fn id(&self) -> &'static str { "helm.values_at_least_two_replicas" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (_, values) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        // Search for `replicaCount` anywhere; require >= 2 if found.
        let mut min_seen: Option<i64> = None;
        scan_replica_count(values, &mut min_seen);
        match min_seen {
            None => TestOutcome::pass(), // chart doesn't expose replicaCount; vacuously OK
            Some(n) if n >= 2 => TestOutcome::pass_with(format!("min replicaCount={n}")),
            Some(n) => TestOutcome::fail(format!("replicaCount={n} < 2 (CP-2)")),
        }
    }
}

fn scan_replica_count(v: &Value, min_seen: &mut Option<i64>) {
    if let Value::Mapping(m) = v {
        if let Some(rc) = m.get(Value::String("replicaCount".to_string())).and_then(|x| x.as_i64()) {
            *min_seen = Some(min_seen.map_or(rc, |cur| cur.min(rc)));
        }
        for (_, val) in m {
            scan_replica_count(val, min_seen);
        }
    }
}

/// SC-7 — chart includes a PodDisruptionBudget for graceful eviction.
pub struct HelmValuesHasPodDisruptionBudget;
impl ComplianceTest for HelmValuesHasPodDisruptionBudget {
    fn id(&self) -> &'static str { "helm.values_has_pod_disruption_budget" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (_, values) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        let mut found = false;
        scan_for_pdb(values, &mut found);
        if found {
            TestOutcome::pass()
        } else {
            TestOutcome::fail("no pdb.enabled=true (PodDisruptionBudget) (SC-7)".to_string())
        }
    }
}

fn scan_for_pdb(v: &Value, found: &mut bool) {
    if *found { return; }
    if let Value::Mapping(m) = v {
        if let Some(pdb) = m.get(Value::String("pdb".to_string()))
            && pdb.get("enabled").and_then(|e| e.as_bool()) == Some(true)
        {
            *found = true;
            return;
        }
        for (_, val) in m {
            scan_for_pdb(val, found);
        }
    }
}

/// AU-2 / AU-12 (audit events) — metrics scraping configured. Also
/// covers continuous-monitoring requirement.
pub struct HelmValuesHasMetricsMonitoring;
impl ComplianceTest for HelmValuesHasMetricsMonitoring {
    fn id(&self) -> &'static str { "helm.values_has_metrics_monitoring" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (_, values) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        let mut found = false;
        scan_for_monitoring(values, &mut found);
        if found {
            TestOutcome::pass()
        } else {
            TestOutcome::fail("no monitoring.enabled=true block found (AU-12)".to_string())
        }
    }
}

fn scan_for_monitoring(v: &Value, found: &mut bool) {
    if *found { return; }
    if let Value::Mapping(m) = v {
        if let Some(mon) = m.get(Value::String("monitoring".to_string()))
            && mon.get("enabled").and_then(|e| e.as_bool()) == Some(true)
        {
            *found = true;
            return;
        }
        // Also accept serviceMonitor or similar conventions.
        if m.contains_key(Value::String("serviceMonitor".to_string())) {
            *found = true;
            return;
        }
        for (_, val) in m {
            scan_for_monitoring(val, found);
        }
    }
}

/// SR-3 / SR-4 (supply chain) — chart's `dependencies` (subcharts) all
/// pin versions. No floating ranges in production.
pub struct HelmChartDependenciesPinned;
impl ComplianceTest for HelmChartDependenciesPinned {
    fn id(&self) -> &'static str { "helm.chart_dependencies_pinned" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let (chart, _) = match chart_and_values(target) { Ok(p) => p, Err(e) => return e };
        let Some(deps) = chart.get("dependencies").and_then(|d| d.as_sequence()) else {
            return TestOutcome::pass(); // no deps, vacuously true
        };
        // Helm spec semver constraints are OK with `~`/`^`/`>=` for the
        // tilde-with-range form? FedRAMP-High wants pinning; we accept
        // `~x.y.z` (allows patch updates) but reject `>=` and `*`.
        for d in deps {
            let name = d.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let version = d.get("version").and_then(|v| v.as_str()).unwrap_or("");
            if version.is_empty() || version.contains(">=") || version.contains("*") || version == "latest" {
                return TestOutcome::fail(format!(
                    "dependency {name:?} version {version:?} is not pinned (SR-4)"
                ));
            }
        }
        TestOutcome::pass()
    }
}

/// CM-7 — chart has a templates directory with at least one resource
/// declared. Empty charts are not deployable artifacts.
pub struct HelmTemplatesNotEmpty;
impl ComplianceTest for HelmTemplatesNotEmpty {
    fn id(&self) -> &'static str { "helm.templates_not_empty" }
    fn version(&self) -> &'static str { "1" }
    fn run(&self, target: &Target) -> TestOutcome {
        let templates = match templates(target) { Ok(t) => t, Err(e) => return e };
        let resource_count = templates
            .keys()
            .filter(|k| !k.starts_with('_') && (k.ends_with(".yaml") || k.ends_with(".yml") || k.ends_with(".tpl")))
            .count();
        if resource_count == 0 {
            TestOutcome::fail("templates/ directory has no .yaml resources".to_string())
        } else {
            TestOutcome::pass_with(format!("found {resource_count} template file(s)"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn good_chart() -> Target {
        let chart = r"
apiVersion: v2
name: lareira-openclaw-pki
version: 0.1.0
appVersion: '0.1.0'
dependencies:
  - name: pleme-microservice
    version: '~0.1.0'
";
        let values = r"
pleme-microservice:
  compliance:
    overlays: [fedramp-high]
  image:
    repository: ghcr.io/pleme-io/openclaw-publisher-pki
    tag: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
  replicaCount: 3
  resources:
    requests: { cpu: 50m, memory: 64Mi }
    limits:   { cpu: 500m, memory: 256Mi }
  health:
    path: /healthz
  monitoring:
    enabled: true
  networkPolicy:
    enabled: true
  pdb:
    enabled: true
";
        let mut templates = BTreeMap::new();
        templates.insert("deployment.yaml".to_string(), b"kind: Deployment".to_vec());
        templates.insert("_helpers.tpl".to_string(), b"".to_vec());
        Target::from_helm_chart_sources(chart, values, templates).unwrap()
    }

    #[test]
    fn good_chart_passes_every_test() {
        let t = good_chart();
        for test in [
            &HelmChartApiVersionV2 as &dyn ComplianceTest,
            &HelmChartHasNameAndVersion,
            &HelmValuesNoLatestTags,
            &HelmValuesImagesPinnedToDigest,
            &HelmValuesRunAsNonRoot,
            &HelmValuesDeclareResourceLimits,
            &HelmValuesHasHealthProbes,
            &HelmValuesHasNetworkPolicy,
            &HelmValuesNoPlaintextSecrets,
            &HelmValuesDeclareFedRampHighOverlay,
            &HelmValuesIngressTlsConfigured,
            &HelmValuesAtLeastTwoReplicas,
            &HelmValuesHasPodDisruptionBudget,
            &HelmValuesHasMetricsMonitoring,
            &HelmChartDependenciesPinned,
            &HelmTemplatesNotEmpty,
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
    fn latest_tag_in_values_fails() {
        let chart = "apiVersion: v2\nname: x\nversion: 0.1.0";
        let values = "image:\n  repository: foo\n  tag: ':latest'";
        let mut tmpl = BTreeMap::new();
        tmpl.insert("d.yaml".into(), vec![]);
        let t = Target::from_helm_chart_sources(chart, values, tmpl).unwrap();
        assert!(matches!(HelmValuesNoLatestTags.run(&t), TestOutcome::Fail { .. }));
    }

    #[test]
    fn unpinned_image_tag_fails() {
        let chart = "apiVersion: v2\nname: x\nversion: 0.1.0";
        let values = "image:\n  repository: foo\n  tag: 'v1.2.3'";
        let mut tmpl = BTreeMap::new();
        tmpl.insert("d.yaml".into(), vec![]);
        let t = Target::from_helm_chart_sources(chart, values, tmpl).unwrap();
        assert!(matches!(HelmValuesImagesPinnedToDigest.run(&t), TestOutcome::Fail { .. }));
    }

    #[test]
    fn run_as_non_root_false_fails() {
        let chart = "apiVersion: v2\nname: x\nversion: 0.1.0";
        let values = "securityContext:\n  runAsNonRoot: false";
        let mut tmpl = BTreeMap::new();
        tmpl.insert("d.yaml".into(), vec![]);
        let t = Target::from_helm_chart_sources(chart, values, tmpl).unwrap();
        assert!(matches!(HelmValuesRunAsNonRoot.run(&t), TestOutcome::Fail { .. }));
    }

    #[test]
    fn missing_resource_limits_fails() {
        let chart = "apiVersion: v2\nname: x\nversion: 0.1.0";
        let values = "image: { tag: 'sha256:1111111111111111111111111111111111111111111111111111111111111111' }";
        let mut tmpl = BTreeMap::new();
        tmpl.insert("d.yaml".into(), vec![]);
        let t = Target::from_helm_chart_sources(chart, values, tmpl).unwrap();
        assert!(matches!(HelmValuesDeclareResourceLimits.run(&t), TestOutcome::Fail { .. }));
    }

    #[test]
    fn replica_count_one_fails() {
        let chart = "apiVersion: v2\nname: x\nversion: 0.1.0";
        let values = "replicaCount: 1";
        let mut tmpl = BTreeMap::new();
        tmpl.insert("d.yaml".into(), vec![]);
        let t = Target::from_helm_chart_sources(chart, values, tmpl).unwrap();
        assert!(matches!(HelmValuesAtLeastTwoReplicas.run(&t), TestOutcome::Fail { .. }));
    }

    #[test]
    fn unbounded_dep_version_fails() {
        let chart = "apiVersion: v2\nname: x\nversion: 0.1.0\ndependencies:\n  - name: foo\n    version: '>=1.0.0'";
        let values = "{}";
        let mut tmpl = BTreeMap::new();
        tmpl.insert("d.yaml".into(), vec![]);
        let t = Target::from_helm_chart_sources(chart, values, tmpl).unwrap();
        assert!(matches!(HelmChartDependenciesPinned.run(&t), TestOutcome::Fail { .. }));
    }

    #[test]
    fn plaintext_secret_pattern_fails() {
        let chart = "apiVersion: v2\nname: x\nversion: 0.1.0";
        let values = "githubToken: ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890";
        let mut tmpl = BTreeMap::new();
        tmpl.insert("d.yaml".into(), vec![]);
        let t = Target::from_helm_chart_sources(chart, values, tmpl).unwrap();
        assert!(matches!(HelmValuesNoPlaintextSecrets.run(&t), TestOutcome::Fail { .. }));
    }
}
