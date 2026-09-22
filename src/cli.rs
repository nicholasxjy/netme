use crate::{app::Options, ping::PingOptions};

pub enum Command {
    Monitor(Options),
    Ping(Box<PingOptions>),
    Help,
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let args: Vec<_> = args.into_iter().collect();
    if args.first().is_some_and(|s| s == "ping") {
        return PingOptions::parse(args.into_iter().skip(1))
            .map(|o| o.map_or(Command::Help, |o| Command::Ping(Box::new(o))));
    }
    monitor_options(args).map(|o| o.map_or(Command::Help, Command::Monitor))
}

pub fn monitor_options(args: impl IntoIterator<Item = String>) -> Result<Option<Options>, String> {
    let mut args = args.into_iter();
    let mut interval = 1;
    let mut ascii = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--interval" => {
                interval = args
                    .next()
                    .ok_or("--interval requires an integer 1-60")?
                    .parse()
                    .map_err(|_| "--interval requires an integer 1-60")?;
                if !(1..=60).contains(&interval) {
                    return Err("--interval must be 1-60 seconds".into());
                }
            }
            "--ascii" => ascii = true,
            "--help" | "-h" => {
                println!("netme — macOS/Linux network monitor\n\nUsage: netme [--interval <1-60>] [--ascii]\n       netme ping <target> [options]\n       netme --help | --version\n\nUp/Down or j/k: scroll adapters; Home/End: first/last\nSpace: pin/unpin display; p: public IP (confirmation); q/Ctrl-C: quit\n\nOnly hardware adapters, download/upload and Internal > Router > External.\nNo sudo or public requests at monitor startup. Linux requires iproute2; iw is optional.\nUse netme ping --help for noninteractive resource diagnostics.");
                return Ok(None);
            }
            "--version" | "-V" => {
                println!("netme {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            _ => return Err("unknown argument; try --help".into()),
        }
    }
    Ok(Some(Options { interval, ascii }))
}
