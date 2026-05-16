use std::io::Write;

use crate::{CliError, DaemonAction, Result};

pub fn run(action: DaemonAction) -> Result<()> {
    match action {
        DaemonAction::Start { bind } => {
            descry_daemon::init_tracing();
            let runtime = tokio::runtime::Runtime::new()?;
            runtime
                .block_on(descry_daemon::serve(bind))
                .map_err(|error| CliError::new(error.to_string(), 1))
        }
        DaemonAction::InitToken => init_token(),
    }
}

fn init_token() -> Result<()> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| CliError::new("cannot determine home directory ($HOME is unset)", 1))?;
    let descry_dir = std::path::PathBuf::from(home).join(".descry");
    std::fs::create_dir_all(&descry_dir).map_err(|error| {
        CliError::new(
            format!("failed to create {}: {error}", descry_dir.display()),
            1,
        )
    })?;

    let token = generate_token();
    let token_path = descry_dir.join("daemon.token");
    std::fs::write(&token_path, &token)
        .map_err(|error| CliError::new(format!("failed to write token: {error}"), 1))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).map_err(
            |error| CliError::new(format!("failed to set token file permissions: {error}"), 1),
        )?;
    }

    let mut stdout = std::io::stdout();
    writeln!(stdout, "token written to: {}", token_path.display())
        .map_err(|error| CliError::new(error.to_string(), 1))?;
    writeln!(
        stdout,
        "use 'Authorization: Bearer {token}' when calling /v1/approve"
    )
    .map_err(|error| CliError::new(error.to_string(), 1))?;
    Ok(())
}

fn generate_token() -> String {
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};
    let pid = std::process::id();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(b"descry-daemon-token-v1\n");
    hasher.update(pid.to_le_bytes());
    hasher.update(ts.to_le_bytes());
    let bytes = hasher.finalize();
    bytes.iter().fold(String::new(), |mut acc, b| {
        acc.push_str(&format!("{b:02x}"));
        acc
    })
}
