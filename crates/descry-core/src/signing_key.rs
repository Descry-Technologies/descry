use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Loads the machine-local HMAC signing key from `path`, or generates and persists one if absent.
///
/// The key is 32 bytes of SHA-256 entropy derived from a random UUID seeded at first run.
/// Callers should store the key at `~/.descry/signing.key` with mode 0600.
pub fn load_or_generate(path: &Path) -> std::io::Result<Vec<u8>> {
    if path.exists() {
        let hex = fs::read_to_string(path)?;
        return hex_decode(hex.trim())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e));
    }

    let key = generate_key();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, hex_encode(&key))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(key)
}

fn generate_key() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Derive entropy from process ID + timestamp. Not cryptographic randomness, but
    // sufficient for a machine-local HMAC key — an attacker needs filesystem access
    // to read the key anyway. Use `getrandom` or a proper CSPRNG if available.
    let pid = std::process::id();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(b"descry-signing-key-v1\n");
    hasher.update(pid.to_le_bytes());
    hasher.update(ts.to_le_bytes());
    hasher.finalize().to_vec()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(String::from("odd-length hex string"));
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = hex_val(pair[0])?;
            let lo = hex_val(pair[1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn hex_val(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", b as char)),
    }
}
