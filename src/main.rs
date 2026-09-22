mod app;
mod cli;
mod command;
mod model;
mod ping;
mod platform;
mod proxy;
mod public_ip;
mod ui;

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let is_ping = args.first().is_some_and(|s| s == "ping");
    let code = match cli::parse(args) {
        Ok(cli::Command::Help) => 0,
        Ok(cli::Command::Monitor(options)) => match app::run(options) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("netme: {error}");
                1
            }
        },
        Ok(cli::Command::Ping(options)) => {
            let stdout = std::io::stdout();
            let mut sink = ping::event::TextSink::new(stdout.lock(), options.ascii);
            ping::run(*options, &mut sink).code
        }
        Err(error) => {
            eprintln!("netme: {error}");
            if is_ping {
                2
            } else {
                1
            }
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
}
