mod app;
mod command;
mod model;
mod platform;
mod public_ip;
mod ui;

fn main() {
    if let Err(error) = app::run() {
        eprintln!("netme: {error}");
        std::process::exit(1);
    }
}
