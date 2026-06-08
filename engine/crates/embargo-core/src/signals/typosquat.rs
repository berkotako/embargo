//! `typosquat` — the package name is a near-miss of a popular package: a likely
//! typosquatting / impersonation attempt (`lodahs` for `lodash`, `expresss`,
//! `react-dom` homoglyphs, `cross.env`). Name-based, so it needs no prior
//! version — it fires on a brand-new package, which is exactly when a
//! typosquatted dropper lands.
//!
//! Per SIGNALS.md this returns a weighted finding; policy decides HOLD/DENY.
//! The bundled `POPULAR` list doubles as an allow-list: a name that *is* a known
//! package is benign, so legitimate look-alikes (e.g. `preact` vs `react`) must
//! be listed to avoid false positives.

use super::{finding, weights, VersionArtifact};
use crate::types::{Severity, Signal, SignalType};

/// How a candidate name resembles a popular one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// One edit away (insertion/deletion/substitution/transposition).
    Edit(usize),
    /// Same name once separators (`-_.`) are stripped (`cross.env` ≈ `cross-env`).
    Separator,
    /// Same name once Unicode look-alike characters are folded to ASCII.
    Homoglyph,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Edit(_) => "edit_distance",
            Kind::Separator => "separator",
            Kind::Homoglyph => "homoglyph",
        }
    }
    /// Lower = stronger resemblance, used to pick the best target match.
    fn rank(self) -> usize {
        match self {
            Kind::Separator | Kind::Homoglyph => 0,
            Kind::Edit(d) => d,
        }
    }
}

pub fn detect(current: &VersionArtifact) -> Vec<Signal> {
    let name = current.package.trim().to_lowercase();

    // Scoped packages (`@scope/name`) are namespace-protected; skip for now.
    if name.is_empty() || name.starts_with('@') || name.len() < 3 {
        return vec![];
    }
    // The name IS a known package → legitimate, never a squat of itself.
    if POPULAR.contains(&name.as_str()) {
        return vec![];
    }

    let folded = fold_confusables(&name);
    let name_nosep = strip_separators(&name);
    let name_chars: Vec<char> = name.chars().collect();

    let mut best: Option<(&str, Kind)> = None;
    for &target in POPULAR {
        if target == name {
            continue;
        }
        let kind = classify(&name, &folded, &name_nosep, &name_chars, target);
        if let Some(k) = kind {
            if best.is_none_or(|(_, bk)| k.rank() < bk.rank()) {
                best = Some((target, k));
            }
            if k.rank() == 0 {
                break; // can't do better than an exact look-alike
            }
        }
    }

    let Some((target, kind)) = best else {
        return vec![];
    };

    vec![finding(
        SignalType::Typosquat,
        Severity::Medium,
        weights::TYPOSQUAT,
        serde_json::json!({
            "package": name,
            "resembles": target,
            "kind": kind.label(),
            "edit_distance": match kind { Kind::Edit(d) => Some(d), _ => None },
        }),
    )]
}

/// Decide whether `name` resembles `target`, and how.
fn classify(
    name: &str,
    folded: &str,
    name_nosep: &str,
    name_chars: &[char],
    target: &str,
) -> Option<Kind> {
    // Homoglyph: the name had look-alike chars that fold to the target.
    if folded != name && folded == target {
        return Some(Kind::Homoglyph);
    }
    // Separator squat: identical once `-_.` are removed, but not literally equal.
    if name_nosep == strip_separators(target) && name != target {
        return Some(Kind::Separator);
    }
    // Edit distance. Require the target to be long enough that a single edit is
    // unlikely to be coincidental; allow distance 2 only for longer names.
    let tchars: Vec<char> = target.chars().collect();
    let d = osa_distance(name_chars, &tchars);
    if d == 1 && target.len() >= 4 {
        return Some(Kind::Edit(1));
    }
    if d == 2 && target.len() >= 8 {
        return Some(Kind::Edit(2));
    }
    None
}

fn strip_separators(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .collect()
}

/// Fold a handful of common Unicode confusables to their ASCII look-alikes.
/// Digits are intentionally not folded — legitimate names contain them.
fn fold_confusables(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'а' => 'a', // Cyrillic
            'е' => 'e',
            'о' => 'o',
            'р' => 'p',
            'с' => 'c',
            'х' => 'x',
            'у' => 'y',
            'ѕ' => 's',
            'і' => 'i',
            'ј' => 'j',
            'ԁ' => 'd',
            'ⅼ' | 'ɩ' | 'ı' => 'l',
            'ο' | 'σ' => 'o', // Greek
            'ν' => 'v',
            'α' => 'a',
            'ρ' => 'p',
            'ϲ' => 'c',
            other => other,
        })
        .collect()
}

/// Optimal string alignment (restricted Damerau–Levenshtein) distance. Names are
/// short, so the full DP table is cheap.
fn osa_distance(a: &[char], b: &[char]) -> usize {
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let mut v = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = v;
        }
    }
    d[n][m]
}

/// A curated corpus of widely-depended-upon npm package names. Doubles as an
/// allow-list (exact members are treated as legitimate). Intentionally includes
/// real look-alikes (e.g. `preact`) so they aren't flagged as squats of their
/// neighbours. Tune/extend against real traffic; this is a starting set.
const POPULAR: &[&str] = &[
    "lodash",
    "underscore",
    "react",
    "react-dom",
    "preact",
    "vue",
    "angular",
    "jquery",
    "express",
    "koa",
    "fastify",
    "axios",
    "node-fetch",
    "got",
    "request",
    "superagent",
    "chalk",
    "colors",
    "ansi-styles",
    "commander",
    "yargs",
    "minimist",
    "debug",
    "async",
    "bluebird",
    "rxjs",
    "redux",
    "react-redux",
    "moment",
    "dayjs",
    "date-fns",
    "luxon",
    "webpack",
    "rollup",
    "vite",
    "parcel",
    "esbuild",
    "gulp",
    "grunt",
    "babel-core",
    "typescript",
    "ts-node",
    "tslib",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "chai",
    "sinon",
    "vitest",
    "playwright",
    "puppeteer",
    "cheerio",
    "classnames",
    "prop-types",
    "styled-components",
    "next",
    "nuxt",
    "gatsby",
    "glob",
    "rimraf",
    "mkdirp",
    "fs-extra",
    "chokidar",
    "dotenv",
    "cross-env",
    "concurrently",
    "nodemon",
    "pm2",
    "husky",
    "lint-staged",
    "semver",
    "uuid",
    "nanoid",
    "validator",
    "joi",
    "yup",
    "zod",
    "ramda",
    "immutable",
    "core-js",
    "regenerator-runtime",
    "postcss",
    "autoprefixer",
    "sass",
    "node-sass",
    "less",
    "tailwindcss",
    "cors",
    "body-parser",
    "morgan",
    "helmet",
    "compression",
    "passport",
    "jsonwebtoken",
    "bcrypt",
    "bcryptjs",
    "argon2",
    "mongoose",
    "sequelize",
    "typeorm",
    "prisma",
    "knex",
    "pg",
    "mysql",
    "mysql2",
    "sqlite3",
    "redis",
    "ioredis",
    "socket.io",
    "ws",
    "nodemailer",
    "winston",
    "pino",
    "bunyan",
    "inquirer",
    "ora",
    "execa",
    "shelljs",
    "cross-spawn",
    "form-data",
    "qs",
    "raw-body",
    "mime",
    "mime-types",
    "tar",
    "archiver",
    "sharp",
    "jimp",
    "graphql",
    "apollo-server",
    "express-session",
    "cookie-parser",
    "multer",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::VersionArtifact;

    fn named(name: &str) -> VersionArtifact {
        VersionArtifact {
            package: name.to_string(),
            ..Default::default()
        }
    }

    fn fires_for(name: &str) -> Option<serde_json::Value> {
        let sigs = detect(&named(name));
        sigs.first().map(|s| s.evidence.clone())
    }

    #[test]
    fn legit_popular_name_is_benign() {
        assert!(detect(&named("lodash")).is_empty());
        assert!(detect(&named("react")).is_empty());
        // A real look-alike that is itself popular must not be flagged.
        assert!(detect(&named("preact")).is_empty());
    }

    #[test]
    fn unrelated_name_is_benign() {
        assert!(detect(&named("acme-internal-billing-utils")).is_empty());
        assert!(detect(&named("my-company-design-system")).is_empty());
    }

    #[test]
    fn single_edit_squat_fires() {
        // deletion, transposition, substitution, insertion
        let ev = fires_for("lodahs").expect("lodahs ~ lodash");
        assert_eq!(ev["resembles"], "lodash");
        assert_eq!(ev["kind"], "edit_distance");
        assert!(fires_for("expres").is_some()); // express -1
        assert!(fires_for("expresss").is_some()); // express +1
        assert!(fires_for("axois").is_some()); // axios transposition
    }

    #[test]
    fn separator_squat_fires() {
        let ev = fires_for("cross.env").expect("cross.env ~ cross-env");
        assert_eq!(ev["resembles"], "cross-env");
        assert_eq!(ev["kind"], "separator");
    }

    #[test]
    fn homoglyph_squat_fires() {
        // Cyrillic 'е' in r-e-a-c-t.
        let ev = fires_for("r\u{0435}act").expect("homoglyph react");
        assert_eq!(ev["resembles"], "react");
        assert_eq!(ev["kind"], "homoglyph");
    }

    #[test]
    fn scoped_and_short_names_skipped() {
        assert!(detect(&named("@types/lodash")).is_empty());
        assert!(detect(&named("qs")).is_empty()); // too short to judge
    }
}
