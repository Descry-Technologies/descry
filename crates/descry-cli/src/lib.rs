use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

pub mod commands;

pub type Result<T> = std::result::Result<T, CliError>;

#[derive(Debug)]
pub struct CliError {
    message: String,
    exit_code: i32,
}

impl CliError {
    pub fn new(message: impl Into<String>, exit_code: i32) -> Self {
        Self {
            message: message.into(),
            exit_code,
        }
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CliError {}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> Self {
        Self::new(error.to_string(), 1)
    }
}

#[derive(Debug, Parser)]
#[command(name = "descry", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Evaluate {
        #[arg(long)]
        stdin: bool,
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
        #[arg(long, default_value = ".descry/project.yml")]
        project: PathBuf,
        #[arg(long, default_value = ".")]
        project_root: PathBuf,
        #[arg(long, default_value = ".descry/context.md")]
        context: PathBuf,
        #[arg(long, default_value = ".descry/state")]
        state: PathBuf,
        #[arg(long, default_value = ".descry/state/project-index.json")]
        project_index: PathBuf,
        #[arg(long, default_value = ".descry/memory/approvals.jsonl")]
        approvals: PathBuf,
        #[arg(long, default_value = ".descry/memory/behavior.json")]
        behavior: PathBuf,
        #[arg(long)]
        audit: Option<PathBuf>,
        #[arg(long)]
        no_context: bool,
    },
    Context {
        #[command(subcommand)]
        action: ContextAction,
    },
    Init {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        all: bool,
    },
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    Task {
        #[command(subcommand)]
        action: TaskAction,
    },
    Approve {
        #[arg(long)]
        scope: String,
        #[arg(long)]
        ttl: String,
        #[arg(long, default_value = ".descry/memory/approvals.jsonl")]
        path: PathBuf,
        #[arg(long, default_value = "human")]
        approver: String,
    },
    Approvals {
        #[command(subcommand)]
        action: ApprovalsAction,
    },
    Logs {
        #[command(subcommand)]
        action: LogsAction,
    },
    Scan {
        #[command(subcommand)]
        action: ScanAction,
    },
    Doctor {
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long)]
        fix: bool,
        #[arg(long, value_enum, default_value_t = DoctorAgent::All)]
        agent: DoctorAgent,
        #[arg(long)]
        claude_settings: Option<PathBuf>,
        #[arg(long)]
        codex_hooks: Option<PathBuf>,
        #[arg(long)]
        codex_config: Option<PathBuf>,
        #[arg(long)]
        cursor_hooks: Option<PathBuf>,
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
        #[arg(long, default_value = ".descry/audit.log")]
        audit: PathBuf,
        #[arg(long, default_value = "descry-default-repo")]
        repo_id_hash: String,
    },
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    Demo {
        #[command(subcommand)]
        action: DemoAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum DaemonAction {
    Start {
        #[arg(long, default_value = "127.0.0.1:7777")]
        bind: SocketAddr,
    },
}

#[derive(Debug, Subcommand)]
pub enum ContextAction {
    Build {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(long, default_value = ".descry/state/project-index.json")]
        output_path: PathBuf,
    },
    Show {
        #[arg(long, default_value = ".descry/state/project-index.json")]
        path: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ExpectedVerdict {
    Allow,
    AllowWithLog,
    Ask,
    RequireApproval,
    Block,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DoctorAgent {
    Claude,
    Codex,
    Cursor,
    Git,
    All,
}

#[derive(Debug, Subcommand)]
pub enum PolicyAction {
    Test {
        fixture: PathBuf,
        #[arg(long)]
        expect: ExpectedVerdict,
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum TaskAction {
    Set {
        task: String,
        #[arg(long, default_value = ".descry/context.md")]
        path: PathBuf,
    },
    Get {
        #[arg(long, default_value = ".descry/context.md")]
        path: PathBuf,
    },
    Clear {
        #[arg(long, default_value = ".descry/context.md")]
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum LogsAction {
    Verify {
        #[arg(long, default_value = ".descry/audit.log")]
        path: PathBuf,
        #[arg(long, default_value = "descry-default-repo")]
        repo_id_hash: String,
    },
    Tail {
        #[arg(long, default_value = ".descry/audit.log")]
        path: PathBuf,
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
    },
    Search {
        query: String,
        #[arg(long, default_value = ".descry/audit.log")]
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum ApprovalsAction {
    List {
        #[arg(long, default_value = ".descry/memory/approvals.jsonl")]
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum ScanAction {
    Secrets {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        staged: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum DemoAction {
    InTaskEdit {
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
    },
    Pocketos {
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
    },
    RmRf {
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
    },
    SecretAccess {
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
    },
    OffTaskEdit {
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
    },
    McpPoison {
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
    },
    ProdDelete {
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum HookAction {
    Install {
        #[command(subcommand)]
        action: HookInstallAction,
    },
    Claude {
        #[command(subcommand)]
        action: ClaudeHookAction,
    },
    Codex {
        #[command(subcommand)]
        action: CodexHookAction,
    },
    Cursor {
        #[command(subcommand)]
        action: CursorHookAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum HookInstallAction {
    Claude {
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long)]
        settings: Option<PathBuf>,
        #[arg(long)]
        command: Option<String>,
    },
    Codex {
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long)]
        hooks: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        command: Option<String>,
    },
    Cursor {
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long)]
        hooks: Option<PathBuf>,
        #[arg(long)]
        command: Option<String>,
        #[arg(long)]
        mcp_command: Option<String>,
    },
    Git {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(long, default_value = "pre-push")]
        hook: String,
        #[arg(long)]
        command: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ClaudeHookAction {
    Pretooluse {
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
        #[arg(long, default_value = ".descry/project.yml")]
        project: PathBuf,
        #[arg(long, default_value = ".descry/audit.log")]
        audit: PathBuf,
        #[arg(long, default_value = ".descry/context.md")]
        context: PathBuf,
        #[arg(long, default_value = ".descry/state")]
        state: PathBuf,
        #[arg(long, default_value = ".descry/memory/approvals.jsonl")]
        approvals: PathBuf,
        #[arg(long, default_value = ".descry/policy.yml")]
        asset_policy: PathBuf,
        #[arg(long, default_value = ".descry/memory/behavior.json")]
        behavior: PathBuf,
        #[arg(long, default_value = "descry-default-repo")]
        repo_id_hash: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum CodexHookAction {
    Pretooluse {
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
        #[arg(long, default_value = ".descry/project.yml")]
        project: PathBuf,
        #[arg(long, default_value = ".descry/audit.log")]
        audit: PathBuf,
        #[arg(long, default_value = ".descry/context.md")]
        context: PathBuf,
        #[arg(long, default_value = ".descry/state")]
        state: PathBuf,
        #[arg(long, default_value = ".descry/memory/approvals.jsonl")]
        approvals: PathBuf,
        #[arg(long, default_value = ".descry/policy.yml")]
        asset_policy: PathBuf,
        #[arg(long, default_value = ".descry/memory/behavior.json")]
        behavior: PathBuf,
        #[arg(long, default_value = "descry-default-repo")]
        repo_id_hash: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum CursorHookAction {
    BeforeShellExecution {
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
        #[arg(long, default_value = ".descry/project.yml")]
        project: PathBuf,
        #[arg(long, default_value = ".descry/audit.log")]
        audit: PathBuf,
        #[arg(long, default_value = ".descry/context.md")]
        context: PathBuf,
        #[arg(long, default_value = ".descry/state")]
        state: PathBuf,
        #[arg(long, default_value = ".descry/memory/approvals.jsonl")]
        approvals: PathBuf,
        #[arg(long, default_value = ".descry/policy.yml")]
        asset_policy: PathBuf,
        #[arg(long, default_value = ".descry/memory/behavior.json")]
        behavior: PathBuf,
        #[arg(long, default_value = "descry-default-repo")]
        repo_id_hash: String,
    },
    BeforeMcpExecution {
        #[arg(long, default_value = "policies/safe-defaults.yml")]
        policy: PathBuf,
        #[arg(long, default_value = ".descry/project.yml")]
        project: PathBuf,
        #[arg(long, default_value = ".descry/audit.log")]
        audit: PathBuf,
        #[arg(long, default_value = ".descry/context.md")]
        context: PathBuf,
        #[arg(long, default_value = ".descry/state")]
        state: PathBuf,
        #[arg(long, default_value = ".descry/memory/approvals.jsonl")]
        approvals: PathBuf,
        #[arg(long, default_value = ".descry/policy.yml")]
        asset_policy: PathBuf,
        #[arg(long, default_value = ".descry/memory/behavior.json")]
        behavior: PathBuf,
        #[arg(long, default_value = "descry-default-repo")]
        repo_id_hash: String,
    },
}

pub fn run(cli: Cli) -> Result<()> {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();

    run_with_io(cli, &mut stdin, &mut stdout, &mut stderr)
}

pub fn run_with_io(
    cli: Cli,
    input: &mut dyn Read,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> Result<()> {
    match cli.command {
        Commands::Evaluate {
            stdin,
            policy,
            project,
            project_root,
            context,
            state,
            project_index,
            approvals,
            behavior,
            audit,
            no_context,
        } => commands::evaluate::run(
            stdin,
            commands::evaluate::EvaluateConfig {
                policy,
                project,
                project_root,
                context,
                state,
                project_index,
                approvals,
                behavior,
                audit,
                no_context,
            },
            input,
            output,
            error,
        ),
        Commands::Context { action } => commands::context::run(action, output),
        Commands::Init {
            project,
            dry_run,
            all,
        } => commands::init::run(
            commands::init::InitConfig {
                project,
                dry_run,
                install_hooks: all,
            },
            output,
        ),
        Commands::Daemon { action } => commands::daemon::run(action),
        Commands::Policy { action } => commands::policy::run(action, output),
        Commands::Task { action } => commands::task::run(action, output),
        Commands::Approve {
            scope,
            ttl,
            path,
            approver,
        } => commands::approve::run(scope, ttl, path, approver, output),
        Commands::Approvals { action } => commands::approve::run_approvals(action, output),
        Commands::Logs { action } => commands::logs::run(action, output, error),
        Commands::Scan { action } => commands::scan::run(action, output),
        Commands::Doctor {
            project,
            fix,
            agent,
            claude_settings,
            codex_hooks,
            codex_config,
            cursor_hooks,
            policy,
            audit,
            repo_id_hash,
        } => commands::doctor::run(
            commands::doctor::DoctorConfig {
                project,
                fix,
                agent,
                claude_settings,
                codex_hooks,
                codex_config,
                cursor_hooks,
                policy,
                audit,
                repo_id_hash,
            },
            output,
        ),
        Commands::Hook { action } => commands::hook::run(action, input, output, error),
        Commands::Demo { action } => commands::demo::run(action, output),
    }
}
