use std::path::PathBuf;

use clap::Parser;
use log::error;
use sysinfo::{ProcessExt, System, SystemExt};
use yai::{inject_into, InjectorError};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(
    name = "yai",
    version = "0.1.3",
    about = "Yet Another Injector for windows x64 dlls."
)]
struct Args {
    /// Process name to inject into.
    #[clap(short, long, value_parser)]
    target: String,

    /// Relative path to payload dll.
    #[clap(short, long, value_parser)]
    payload: PathBuf,
}

fn main() -> Result<(), InjectorError> {
    std::env::set_var("RUST_LOG", "info");
    pretty_env_logger::init();

    let Args { target, payload } = Args::parse();

    let mut sys = System::new_all();
    sys.refresh_processes();
    let process = sys.processes_by_name(&target).next();
    let process = match process {
        Some(process) => process,
        None => {
            error!("Process does not exist/is not actively running");
            return Err(InjectorError::ProcessNotActive(target));
        }
    };

    inject_into(payload, process.pid())
}
