use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use descry_core::AssetGraphNode;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectIndex {
    pub repo_root: PathBuf,
    pub repo_name: String,
    pub branch: Option<String>,
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
    pub source_paths: Vec<String>,
    pub test_paths: Vec<String>,
    pub infra_paths: Vec<String>,
    pub config_paths: Vec<String>,
    pub secret_paths: Vec<String>,
    pub deploy_paths: Vec<String>,
    #[serde(default)]
    pub asset_graph: Vec<AssetGraphNode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionEvent {
    pub timestamp_unix: u64,
    pub session_id: Option<String>,
    pub harness: String,
    pub user_prompt: Option<String>,
    pub action_type: String,
    pub target: String,
    pub decision: Option<String>,
}

pub fn build_project_index(repo_root: &Path) -> io::Result<ProjectIndex> {
    let repo_root = fs::canonicalize(repo_root)?;
    let mut builder = ProjectIndexBuilder::new(&repo_root);
    builder.scan_dir(&repo_root)?;
    Ok(builder.finish())
}

pub fn write_project_index(index: &ProjectIndex, path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(index)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    fs::write(path, format!("{body}\n"))
}

pub fn read_project_index(path: &Path) -> io::Result<ProjectIndex> {
    let body = fs::read_to_string(path)?;
    serde_json::from_str(&body).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn read_codeowners_patterns(repo_root: &Path) -> io::Result<Vec<String>> {
    for relative_path in [
        ".github/CODEOWNERS",
        "CODEOWNERS",
        "docs/CODEOWNERS",
        ".gitlab/CODEOWNERS",
    ] {
        let path = repo_root.join(relative_path);
        if path.exists() {
            return parse_codeowners_patterns(&fs::read_to_string(path)?);
        }
    }

    Ok(Vec::new())
}

fn parse_codeowners_patterns(body: &str) -> io::Result<Vec<String>> {
    let mut patterns = body
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            line.split_whitespace()
                .next()
                .filter(|pattern| !pattern.is_empty())
                .map(ToString::to_string)
        })
        .collect::<Vec<_>>();
    patterns.sort();
    patterns.dedup();
    Ok(patterns)
}

pub fn append_session_event(state_dir: &Path, event: &SessionEvent) -> io::Result<()> {
    fs::create_dir_all(state_dir.join("sessions"))?;

    append_bounded_jsonl(&state_dir.join("recent-actions.jsonl"), event, 200)?;

    let session_file = state_dir.join("sessions").join(format!(
        "{}.jsonl",
        session_file_id(event.session_id.as_deref())
    ));
    append_bounded_jsonl(&session_file, event, 200)
}

pub fn read_recent_events(state_dir: &Path) -> io::Result<Vec<SessionEvent>> {
    read_jsonl(&state_dir.join("recent-actions.jsonl"))
}

pub fn sanitized_event_target(action_type: &str, target: &str) -> String {
    match action_type {
        "shell.exec" => String::from("<shell command omitted>"),
        "mcp.call" => target.to_string(),
        _ => target.to_string(),
    }
}

fn append_bounded_jsonl(path: &Path, event: &SessionEvent, max_records: usize) -> io::Result<()> {
    let mut records = read_jsonl(path).unwrap_or_default();
    records.push(event.clone());
    if records.len() > max_records {
        records = records.split_off(records.len() - max_records);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    for record in records {
        serde_json::to_writer(&mut file, &record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        file.write_all(b"\n")?;
    }
    file.flush()
}

fn read_jsonl(path: &Path) -> io::Result<Vec<SessionEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = OpenOptions::new().read(true).open(path)?;
    let mut records = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let event = serde_json::from_str(&line)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        records.push(event);
    }
    Ok(records)
}

fn session_file_id(session_id: Option<&str>) -> String {
    let raw = session_id.unwrap_or("unknown");
    let sanitized: String = raw
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        String::from("unknown")
    } else {
        sanitized
    }
}

struct ProjectIndexBuilder {
    repo_root: PathBuf,
    languages: BTreeSet<String>,
    frameworks: BTreeSet<String>,
    source_paths: BTreeSet<String>,
    test_paths: BTreeSet<String>,
    infra_paths: BTreeSet<String>,
    config_paths: BTreeSet<String>,
    secret_paths: BTreeSet<String>,
    deploy_paths: BTreeSet<String>,
    asset_graph: BTreeMap<String, AssetGraphNode>,
}

impl ProjectIndexBuilder {
    fn new(repo_root: &Path) -> Self {
        Self {
            repo_root: repo_root.to_path_buf(),
            languages: BTreeSet::new(),
            frameworks: BTreeSet::new(),
            source_paths: BTreeSet::new(),
            test_paths: BTreeSet::new(),
            infra_paths: BTreeSet::new(),
            config_paths: BTreeSet::new(),
            secret_paths: BTreeSet::new(),
            deploy_paths: BTreeSet::new(),
            asset_graph: BTreeMap::new(),
        }
    }

    fn scan_dir(&mut self, dir: &Path) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();

            if path.is_dir() {
                if ignored_dir(&file_name) {
                    continue;
                }
                self.classify_path(&path);
                self.scan_dir(&path)?;
            } else if path.is_file() {
                self.classify_path(&path);
            }
        }

        Ok(())
    }

    fn classify_path(&mut self, path: &Path) {
        let Some(relative_path) = relative_slash_path(&self.repo_root, path) else {
            return;
        };
        let basename = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        let lowercase = relative_path.to_ascii_lowercase();

        self.detect_language(&relative_path, &basename);
        self.detect_framework(&relative_path, &basename);

        if is_source_path(&relative_path) {
            self.source_paths.insert(top_level_bucket(&relative_path));
        }
        if is_test_path(&relative_path) {
            self.test_paths.insert(top_level_bucket(&relative_path));
        }
        if is_infra_path(&relative_path) {
            self.infra_paths.insert(top_level_bucket(&relative_path));
        }
        if is_config_path(&relative_path, &basename) {
            self.config_paths.insert(relative_path.clone());
        }
        if is_secret_path(&lowercase, &basename.to_ascii_lowercase()) {
            self.secret_paths.insert(relative_path.clone());
        }
        if is_deploy_path(&lowercase) {
            self.deploy_paths.insert(relative_path);
        }
        self.detect_asset_graph_node(&lowercase);
    }

    fn detect_language(&mut self, relative_path: &str, basename: &str) {
        match basename {
            "Cargo.toml" => {
                self.languages.insert(String::from("rust"));
            }
            "package.json" => {
                self.languages.insert(String::from("javascript"));
            }
            "pyproject.toml" => {
                self.languages.insert(String::from("python"));
            }
            "go.mod" => {
                self.languages.insert(String::from("go"));
            }
            _ => {}
        }

        if relative_path.ends_with(".rs") {
            self.languages.insert(String::from("rust"));
        } else if relative_path.ends_with(".ts") || relative_path.ends_with(".tsx") {
            self.languages.insert(String::from("typescript"));
        } else if relative_path.ends_with(".js") || relative_path.ends_with(".jsx") {
            self.languages.insert(String::from("javascript"));
        } else if relative_path.ends_with(".py") {
            self.languages.insert(String::from("python"));
        } else if relative_path.ends_with(".go") {
            self.languages.insert(String::from("go"));
        }
    }

    fn detect_framework(&mut self, relative_path: &str, basename: &str) {
        if basename == "Cargo.toml" {
            self.frameworks.insert(String::from("cargo"));
        } else if basename == "package.json" {
            self.frameworks.insert(String::from("node"));
        } else if basename == "pyproject.toml" {
            self.frameworks.insert(String::from("python-packaging"));
        } else if basename == "go.mod" {
            self.frameworks.insert(String::from("go-modules"));
        } else if relative_path.starts_with("pages/") || relative_path.starts_with("app/") {
            self.frameworks.insert(String::from("web-app"));
        }
    }

    fn detect_asset_graph_node(&mut self, lowercase_path: &str) {
        if let Some((provider, pattern)) = hosted_control_plane_config(lowercase_path) {
            let node_id = format!("hosted-control-plane:{provider}");
            self.asset_graph
                .entry(node_id.clone())
                .or_insert_with(|| AssetGraphNode {
                    id: node_id,
                    asset_type: String::from("hosted_control_plane"),
                    sensitivity: String::from("critical"),
                    environment: String::from("production_relevant"),
                    default_action: String::from("require_approval"),
                    patterns: Vec::new(),
                    evidence: Vec::new(),
                });
            if let Some(node) = self
                .asset_graph
                .get_mut(&format!("hosted-control-plane:{provider}"))
            {
                push_unique(&mut node.patterns, pattern.to_string());
                push_unique(&mut node.evidence, format!("file:{lowercase_path}"));
            }
        }
    }

    fn finish(self) -> ProjectIndex {
        ProjectIndex {
            repo_name: self
                .repo_root
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| String::from("unknown")),
            branch: read_branch(&self.repo_root),
            repo_root: self.repo_root,
            languages: into_vec(self.languages),
            frameworks: into_vec(self.frameworks),
            source_paths: into_vec(self.source_paths),
            test_paths: into_vec(self.test_paths),
            infra_paths: into_vec(self.infra_paths),
            config_paths: into_vec(self.config_paths),
            secret_paths: into_vec(self.secret_paths),
            deploy_paths: into_vec(self.deploy_paths),
            asset_graph: self.asset_graph.into_values().collect(),
        }
    }
}

fn hosted_control_plane_config(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        "railway.toml" => Some(("railway", "railway.toml")),
        "fly.toml" => Some(("fly", "fly.toml")),
        "vercel.json" | ".vercel/project.json" => Some(("vercel", "vercel.json")),
        _ => None,
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
        values.sort();
    }
}

fn ignored_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "node_modules" | "target" | "dist" | "build" | ".next" | "coverage"
    )
}

fn is_source_path(path: &str) -> bool {
    path.starts_with("src/")
        || path.starts_with("crates/")
        || path.starts_with("app/")
        || path.starts_with("pages/")
}

fn is_test_path(path: &str) -> bool {
    path.starts_with("tests/") || path.contains("/tests/") || path.contains("__tests__")
}

fn is_infra_path(path: &str) -> bool {
    path.starts_with("infra/")
        || path.starts_with("terraform/")
        || path.starts_with(".github/workflows/")
}

fn is_config_path(path: &str, basename: &str) -> bool {
    matches!(
        basename,
        "Cargo.toml" | "package.json" | "pyproject.toml" | "go.mod" | "Dockerfile"
    ) || path.ends_with(".yml")
        || path.ends_with(".yaml")
        || path.ends_with(".toml")
        || path.ends_with(".json")
}

fn is_secret_path(lowercase_path: &str, lowercase_basename: &str) -> bool {
    lowercase_basename.starts_with(".env")
        || lowercase_path.ends_with(".pem")
        || lowercase_path.ends_with(".key")
        || lowercase_path.contains("secret")
        || lowercase_path.contains("token")
}

fn is_deploy_path(lowercase_path: &str) -> bool {
    lowercase_path.contains("deploy")
        || lowercase_path.contains("release")
        || lowercase_path.contains("prod")
        || lowercase_path.contains("railway")
        || lowercase_path.contains("fly")
        || lowercase_path.contains("vercel")
        || lowercase_path.contains("aws")
        || lowercase_path.contains("gcloud")
}

fn relative_slash_path(root: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(root)
        .ok()
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
}

fn top_level_bucket(path: &str) -> String {
    if path.starts_with(".github/workflows/") {
        String::from(".github/workflows")
    } else if let Some((first, _)) = path.split_once('/') {
        format!("{first}/**")
    } else {
        path.to_string()
    }
}

fn read_branch(repo_root: &Path) -> Option<String> {
    let head = fs::read_to_string(repo_root.join(".git/HEAD")).ok()?;
    let head = head.trim();
    head.strip_prefix("ref: refs/heads/")
        .map(ToString::to_string)
        .or_else(|| Some(head.to_string()).filter(|value| !value.is_empty()))
}

fn into_vec(values: BTreeSet<String>) -> Vec<String> {
    values.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{append_session_event, read_recent_events, sanitized_event_target, SessionEvent};
    use super::{build_project_index, read_codeowners_patterns};

    #[test]
    fn indexes_rust_workspace_shape() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        write(tempdir.path().join("Cargo.toml"), "[workspace]\n");
        write(tempdir.path().join("crates/app/src/lib.rs"), "");
        write(tempdir.path().join("tests/integration.rs"), "");
        write(tempdir.path().join(".github/workflows/ci.yml"), "");
        write(tempdir.path().join("railway.toml"), "");
        write(tempdir.path().join(".env.production"), "");
        write(tempdir.path().join("target/debug/generated.rs"), "");
        write(tempdir.path().join(".git/HEAD"), "ref: refs/heads/main\n");

        let index = build_project_index(tempdir.path()).expect("index builds");

        assert_eq!(index.branch.as_deref(), Some("main"));
        assert!(index.languages.contains(&String::from("rust")));
        assert!(index.source_paths.contains(&String::from("crates/**")));
        assert!(index.test_paths.contains(&String::from("tests/**")));
        assert!(index
            .infra_paths
            .contains(&String::from(".github/workflows")));
        assert!(index
            .secret_paths
            .contains(&String::from(".env.production")));
        assert!(index.asset_graph.iter().any(|node| {
            node.id == "hosted-control-plane:railway"
                && node.patterns.contains(&String::from("railway.toml"))
        }));
        assert!(!index.source_paths.contains(&String::from("target/**")));
    }

    #[test]
    fn indexes_javascript_app_shape() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        write(tempdir.path().join("package.json"), "{}");
        write(tempdir.path().join("app/page.tsx"), "");
        write(tempdir.path().join("src/auth/session.ts"), "");
        write(tempdir.path().join("scripts/deploy/prod.sh"), "");
        write(tempdir.path().join("node_modules/pkg/index.js"), "");

        let index = build_project_index(tempdir.path()).expect("index builds");

        assert!(index.languages.contains(&String::from("javascript")));
        assert!(index.languages.contains(&String::from("typescript")));
        assert!(index.frameworks.contains(&String::from("node")));
        assert!(index.frameworks.contains(&String::from("web-app")));
        assert!(index.source_paths.contains(&String::from("app/**")));
        assert!(index.deploy_paths.contains(&String::from("scripts/deploy")));
        assert!(!index
            .source_paths
            .contains(&String::from("node_modules/**")));
    }

    #[test]
    fn reads_codeowners_patterns_in_stable_order() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        write(
            tempdir.path().join(".github/CODEOWNERS"),
            r#"
# comment
src/auth/** @auth-team
*.md @docs
src/auth/** @auth-team
"#,
        );

        let patterns = read_codeowners_patterns(tempdir.path()).expect("codeowners reads");

        assert_eq!(
            patterns,
            vec![String::from("*.md"), String::from("src/auth/**")]
        );
    }

    #[test]
    fn appends_bounded_sanitized_session_events() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let state_dir = tempdir.path().join(".descry/state");

        for index in 0..205 {
            append_session_event(
                &state_dir,
                &SessionEvent {
                    timestamp_unix: index,
                    session_id: Some(String::from("s/1")),
                    harness: String::from("claude-code"),
                    user_prompt: None,
                    action_type: String::from("shell.exec"),
                    target: sanitized_event_target("shell.exec", "rm -rf ~"),
                    decision: Some(String::from("block")),
                },
            )
            .expect("event appends");
        }

        let recent = read_recent_events(&state_dir).expect("recent events read");
        assert_eq!(recent.len(), 200);
        assert_eq!(recent[0].timestamp_unix, 5);
        assert_eq!(recent[199].target, "<shell command omitted>");
        assert!(state_dir.join("sessions/s_1.jsonl").exists());
    }

    fn write(path: std::path::PathBuf, body: &str) {
        fs::create_dir_all(path.parent().expect("path has parent")).expect("parent creates");
        fs::write(path, body).expect("file writes");
    }
}
