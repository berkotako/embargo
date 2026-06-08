use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid glob in scope '{scope}': {source}")]
    InvalidGlob {
        scope: String,
        source: globset::Error,
    },
    #[error("policy ruleset has no rules")]
    EmptyRuleset,
    #[error("unsupported policy schema version {0}; expected 1")]
    UnsupportedVersion(u32),
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// A single policy rule as authored in YAML / stored in Postgres.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Comma-separated list of globs over package names.
    pub scope: String,
    /// Hours new versions must age before ALLOW. 0 = bypass cooldown.
    pub cooldown_hours: u64,
    pub require_provenance: bool,
    pub on_hard_signal: OnHardSignal,
    #[serde(default)]
    pub fast_track: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnHardSignal {
    Deny,
    Hold,
}

/// The versioned policy ruleset (corresponds to policy.schema.json version:1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleset {
    pub version: u32,
    pub rules: Vec<PolicyRule>,
}

impl PolicyRuleset {
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let ruleset: PolicyRuleset = serde_yaml::from_str(yaml)?;
        if ruleset.version != 1 {
            return Err(PolicyError::UnsupportedVersion(ruleset.version));
        }
        if ruleset.rules.is_empty() {
            return Err(PolicyError::EmptyRuleset);
        }
        Ok(ruleset)
    }
}

/// Specificity score for a single glob pattern. Higher = more specific.
fn glob_specificity(pattern: &str) -> u32 {
    if pattern == "**" {
        return 0;
    }
    // Scoped wildcard: @scope/*
    if pattern.starts_with('@') && pattern.ends_with("/*") {
        return 2;
    }
    // Exact scoped name: @scope/name
    if pattern.starts_with('@') && !pattern.ends_with("/*") {
        return if pattern.contains('*') { 1 } else { 4 };
    }
    // Bare wildcard glob (contains * but isn't **)
    if pattern.contains('*') {
        return 1;
    }
    // Exact bare name
    4
}

/// Specificity (0–4) of a rule `scope`, which may be a comma-separated glob
/// list — the best (highest) of its globs. The console renders this 1–4.
pub fn scope_specificity(scope: &str) -> u32 {
    scope
        .split(',')
        .map(|g| glob_specificity(g.trim()))
        .max()
        .unwrap_or(0)
}

/// Compiled rule ready for fast matching.
struct CompiledRule {
    globs: GlobSet,
    /// Best (highest) specificity score among the globs in this rule's scope.
    specificity: u32,
    /// Index into the original `rules` vec — used for tie-breaking (earlier = wins).
    index: usize,
}

/// Resolver that answers: given a package name, which rule wins?
pub struct PolicyResolver {
    compiled: Vec<CompiledRule>,
    rules: Vec<PolicyRule>,
}

impl PolicyResolver {
    pub fn new(ruleset: &PolicyRuleset) -> Result<Self, PolicyError> {
        let mut compiled = Vec::with_capacity(ruleset.rules.len());

        for (index, rule) in ruleset.rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            let patterns: Vec<&str> = rule.scope.split(',').map(str::trim).collect();
            let mut builder = GlobSetBuilder::new();
            let mut best_specificity = 0u32;

            for pat in &patterns {
                let glob = Glob::new(pat).map_err(|source| PolicyError::InvalidGlob {
                    scope: rule.scope.clone(),
                    source,
                })?;
                builder.add(glob);
                best_specificity = best_specificity.max(glob_specificity(pat));
            }

            compiled.push(CompiledRule {
                globs: builder.build().map_err(|source| PolicyError::InvalidGlob {
                    scope: rule.scope.clone(),
                    source,
                })?,
                specificity: best_specificity,
                index,
            });
        }

        Ok(Self {
            compiled,
            rules: ruleset.rules.clone(),
        })
    }

    /// Returns the winning rule for `package`, or `None` if no enabled rule matches.
    /// Most-specific-wins; tie-broken by earlier index.
    pub fn resolve<'a>(&'a self, package: &str) -> Option<&'a PolicyRule> {
        let mut best: Option<(u32, usize)> = None; // (specificity, rule index)

        for cr in &self.compiled {
            if cr.globs.is_match(package) {
                let beats = match best {
                    None => true,
                    Some((best_spec, best_idx)) => {
                        cr.specificity > best_spec
                            || (cr.specificity == best_spec && cr.index < best_idx)
                    }
                };
                if beats {
                    best = Some((cr.specificity, cr.index));
                }
            }
        }

        best.map(|(_, idx)| &self.rules[idx])
    }

    /// Whether `package` is in the fast_track list of its winning rule.
    pub fn is_fast_tracked(&self, package: &str) -> bool {
        self.resolve(package)
            .map(|r| r.fast_track.iter().any(|ft| ft == package))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ruleset(yaml: &str) -> PolicyRuleset {
        PolicyRuleset::from_yaml(yaml).unwrap()
    }

    fn resolver(yaml: &str) -> PolicyResolver {
        PolicyResolver::new(&make_ruleset(yaml)).unwrap()
    }

    const BASIC_POLICY: &str = r#"
version: 1
rules:
  - scope: "@mycompany/*"
    cooldown_hours: 0
    require_provenance: true
    on_hard_signal: deny
    fast_track:
      - "@mycompany/design-tokens"
    enabled: true
  - scope: "@types/*"
    cooldown_hours: 6
    require_provenance: false
    on_hard_signal: deny
    enabled: true
  - scope: "**"
    cooldown_hours: 72
    require_provenance: false
    on_hard_signal: deny
    enabled: true
"#;

    #[test]
    fn scoped_wildcard_beats_catch_all() {
        let r = resolver(BASIC_POLICY);
        let rule = r.resolve("@mycompany/auth").unwrap();
        assert_eq!(rule.cooldown_hours, 0);
        assert!(rule.require_provenance);
    }

    #[test]
    fn types_scope_beats_catch_all() {
        let r = resolver(BASIC_POLICY);
        let rule = r.resolve("@types/node").unwrap();
        assert_eq!(rule.cooldown_hours, 6);
    }

    #[test]
    fn catch_all_for_unscoped() {
        let r = resolver(BASIC_POLICY);
        let rule = r.resolve("lodash").unwrap();
        assert_eq!(rule.cooldown_hours, 72);
    }

    #[test]
    fn fast_track_detected() {
        let r = resolver(BASIC_POLICY);
        assert!(r.is_fast_tracked("@mycompany/design-tokens"));
        assert!(!r.is_fast_tracked("@mycompany/auth"));
        assert!(!r.is_fast_tracked("lodash"));
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let yaml = r#"
version: 1
rules:
  - scope: "@mycompany/*"
    cooldown_hours: 0
    require_provenance: true
    on_hard_signal: deny
    enabled: false
  - scope: "**"
    cooldown_hours: 72
    require_provenance: false
    on_hard_signal: deny
    enabled: true
"#;
        let r = resolver(yaml);
        let rule = r.resolve("@mycompany/auth").unwrap();
        // disabled rule is skipped; catch-all wins
        assert_eq!(rule.cooldown_hours, 72);
    }

    #[test]
    fn exact_name_beats_scoped_wildcard() {
        let yaml = r#"
version: 1
rules:
  - scope: "@mycompany/*"
    cooldown_hours: 0
    require_provenance: true
    on_hard_signal: deny
    enabled: true
  - scope: "@mycompany/auth"
    cooldown_hours: 48
    require_provenance: true
    on_hard_signal: deny
    enabled: true
  - scope: "**"
    cooldown_hours: 72
    require_provenance: false
    on_hard_signal: deny
    enabled: true
"#;
        let r = resolver(yaml);
        let rule = r.resolve("@mycompany/auth").unwrap();
        // exact match (score 4) beats @mycompany/* (score 2)
        assert_eq!(rule.cooldown_hours, 48);
    }

    #[test]
    fn comma_scope_matches_any() {
        let yaml = r#"
version: 1
rules:
  - scope: "express,axios,react"
    cooldown_hours: 24
    require_provenance: true
    on_hard_signal: deny
    enabled: true
  - scope: "**"
    cooldown_hours: 72
    require_provenance: false
    on_hard_signal: deny
    enabled: true
"#;
        let r = resolver(yaml);
        assert_eq!(r.resolve("express").unwrap().cooldown_hours, 24);
        assert_eq!(r.resolve("axios").unwrap().cooldown_hours, 24);
        assert_eq!(r.resolve("react").unwrap().cooldown_hours, 24);
        assert_eq!(r.resolve("lodash").unwrap().cooldown_hours, 72);
    }

    #[test]
    fn unsupported_version_errors() {
        let yaml = "version: 2\nrules: []";
        assert!(matches!(
            PolicyRuleset::from_yaml(yaml),
            Err(PolicyError::UnsupportedVersion(2))
        ));
    }
}
