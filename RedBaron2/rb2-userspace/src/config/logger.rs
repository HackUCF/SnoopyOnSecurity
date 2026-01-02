use env_logger::Env;
use log::LevelFilter;

/// Call this early (e.g. at the top of `main()`).
pub fn init() {
    // `filter_or("RUST_LOG", "info")` means:
    //   • if $RUST_LOG is set, use that
    //   • otherwise default to "info"
    let env = Env::default()
        .filter_or("RUST_LOG", "info")
        .write_style_or("RUST_LOG_STYLE", "always");

    // Don’t shove a second `.filter_level(...)` here.
    env_logger::Builder::from_env(env)
        .filter_module("aya_obj", LevelFilter::Info) // aya spams debug logs
        // (optional) e.g. `.format_timestamp(Some("%Y-%m-%d %H:%M:%S"))`
        .init();
}
