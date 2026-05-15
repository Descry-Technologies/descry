/// Descry standalone audit chain verifier.
///
/// Usage:
///   descry-verify --chain <path> [--repo-id <hash>] [--export-bundle]
///
/// Exits 0 if the chain is intact, 1 if it is broken or missing, 2 on
/// usage/IO errors.  Writes a JSON result to stdout.
use std::path::PathBuf;
use std::process;

use descry_audit::{export_bundle, verify_file, VerifyOutcome};
use serde_json::json;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match run(&args[1..]) {
        Ok(exit_code) => process::exit(exit_code),
        Err(message) => {
            eprintln!("{}", json!({ "error": message }));
            process::exit(2);
        }
    }
}

fn run(args: &[String]) -> Result<i32, String> {
    let mut chain_path: Option<PathBuf> = None;
    let mut repo_id = String::from("descry-default-repo");
    let mut do_export = false;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--chain" => {
                chain_path = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| String::from("--chain requires a path argument"))?,
                ));
            }
            "--repo-id" => {
                repo_id = iter
                    .next()
                    .ok_or_else(|| String::from("--repo-id requires an argument"))?
                    .clone();
            }
            "--export-bundle" => {
                do_export = true;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: descry-verify --chain <path> [--repo-id <hash>] [--export-bundle]"
                );
                return Ok(0);
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
        }
    }

    let chain_path = chain_path.ok_or_else(|| String::from("--chain <path> is required"))?;

    if !chain_path.exists() {
        eprintln!(
            "{}",
            json!({ "error": format!("chain file not found: {}", chain_path.display()) })
        );
        return Ok(1);
    }

    if do_export {
        let bundle = export_bundle(&chain_path, &repo_id)
            .map_err(|e| format!("export failed: {e}"))?;
        println!(
            "{}",
            serde_json::to_string_pretty(&bundle)
                .map_err(|e| format!("serialization failed: {e}"))?
        );
        return Ok(0);
    }

    let outcome = verify_file(&chain_path, &repo_id);
    match &outcome {
        VerifyOutcome::Ok { records } => {
            println!(
                "{}",
                json!({
                    "status": "ok",
                    "records": records,
                    "chain": chain_path.display().to_string(),
                    "repo_id": repo_id,
                })
            );
            Ok(0)
        }
        VerifyOutcome::Broken { at_seq, reason } => {
            println!(
                "{}",
                json!({
                    "status": "broken",
                    "at_seq": at_seq,
                    "reason": reason,
                    "chain": chain_path.display().to_string(),
                    "repo_id": repo_id,
                })
            );
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn missing_chain_flag_returns_error() {
        let err = run(&[]).unwrap_err();
        assert!(err.contains("--chain"));
    }

    #[test]
    fn nonexistent_chain_exits_one() {
        let code = run(&[
            String::from("--chain"),
            String::from("/nonexistent/path/audit.log"),
        ])
        .expect("run completes");
        assert_eq!(code, 1);
    }

    #[test]
    fn help_flag_exits_zero() {
        let code = run(&[String::from("--help")]).expect("run completes");
        assert_eq!(code, 0);
    }
}
