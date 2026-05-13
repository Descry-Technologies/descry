use crate::{CliError, DaemonAction, Result};

pub fn run(action: DaemonAction) -> Result<()> {
    match action {
        DaemonAction::Start { bind } => {
            let runtime = tokio::runtime::Runtime::new()?;
            runtime
                .block_on(descry_daemon::serve(bind))
                .map_err(|error| CliError::new(error.to_string(), 1))
        }
    }
}
