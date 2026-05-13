use descry_policy::ProjectPolicy;

#[test]
fn project_policy_matches_launch_asset_rules() {
    let policy = ProjectPolicy::load_yaml(
        r#"
project:
  name: descry

assets:
  - id: secrets
    patterns: [".env*", "**/*secret*", "**/*token*", "~/.ssh/**"]
    sensitivity: critical
    default_action: block

  - id: infra
    patterns: ["infra/**", "terraform/**", ".github/workflows/**", "scripts/deploy/**"]
    sensitivity: high
    default_action: require_approval

  - id: source
    patterns: ["src/**", "tests/**", "crates/**"]
    sensitivity: normal
    default_action: allow_if_context_matches

actions:
  destructive:
    default_action: block
  deploy:
    default_action: require_approval
  test:
    default_action: allow
"#,
    )
    .expect("project policy loads");

    let secrets = policy
        .match_asset(".env.production")
        .expect("secret asset matches");
    assert_eq!(secrets.id, "secrets");
    assert_eq!(secrets.sensitivity, "critical");
    assert_eq!(secrets.default_action, "block");

    let infra = policy
        .match_asset(".github/workflows/deploy.yml")
        .expect("infra asset matches");
    assert_eq!(infra.id, "infra");
    assert_eq!(infra.sensitivity, "high");
    assert_eq!(infra.default_action, "require_approval");

    let source = policy
        .match_asset("src/auth/session.ts")
        .expect("source asset matches");
    assert_eq!(source.id, "source");
    assert_eq!(source.sensitivity, "normal");
    assert_eq!(source.default_action, "allow_if_context_matches");
}

#[test]
fn missing_project_policy_uses_safe_builtin_defaults() {
    let policy = ProjectPolicy::default();

    assert_eq!(
        policy
            .match_asset(".env.production")
            .expect("secret asset matches")
            .id,
        "secrets"
    );
    assert_eq!(
        policy
            .match_asset("secret.txt")
            .expect("root secret asset matches")
            .id,
        "secrets"
    );
    assert_eq!(
        policy
            .match_asset(".github/workflows/deploy.yml")
            .expect("infra asset matches")
            .id,
        "infra"
    );
    assert_eq!(
        policy
            .match_asset("src/auth/session.ts")
            .expect("source asset matches")
            .id,
        "source"
    );
}
