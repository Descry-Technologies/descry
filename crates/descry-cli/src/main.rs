use clap::Parser;

fn main() {
    let cli = descry_cli::Cli::parse();

    if let Err(error) = descry_cli::run(cli) {
        if !error.to_string().is_empty() {
            eprintln!("{error}");
        }
        std::process::exit(error.exit_code());
    }
}
