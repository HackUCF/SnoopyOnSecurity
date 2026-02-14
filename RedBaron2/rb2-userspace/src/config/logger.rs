use log::LevelFilter;
use log::warn;
use log4rs::{
    Handle,
    append::console::{ConsoleAppender, Target},
    append::rolling_file::{
        RollingFileAppender,
        policy::compound::{
            CompoundPolicy, roll::fixed_window::FixedWindowRoller, trigger::size::SizeTrigger,
        },
    },
    config::{Appender, Config, Logger, Root, runtime::ConfigBuilder},
    encode::pattern::PatternEncoder,
};
use std::path::Path;
use std::sync::OnceLock;

static HANDLE: OnceLock<Handle> = OnceLock::new();

const CONSOLE_APPENDER: &str = "console";
const CONSOLE_PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S%.3f)} {h({l:5.5})} {t} - {m}{n}";
const FILE_PATTERN: &str = "{m}{n}";

const ROOT_LEVEL: LevelFilter = LevelFilter::Info;
const DEFAULT_LOGGER: (&str, LevelFilter) = ("rb2_userspace", LevelFilter::Info);

fn build_console() -> ConsoleAppender {
    ConsoleAppender::builder()
        .target(Target::Stderr)
        .encoder(Box::new(PatternEncoder::new(CONSOLE_PATTERN)))
        .build()
}

fn build_rolling_file(
    path: &Path,
    rollover_size_bytes: u64,
    rollover_count: u32,
) -> Option<RollingFileAppender> {
    // Keep numbering stable and compress archives.
    let archive_pattern = format!("{}.{{}}.gz", path.display());

    let roller = FixedWindowRoller::builder()
        .build(&archive_pattern, rollover_count)
        .ok()?;

    let trigger = SizeTrigger::new(rollover_size_bytes);
    let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));

    RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(FILE_PATTERN)))
        .build(path, Box::new(policy))
        .ok()
}

fn base_builder() -> ConfigBuilder {
    Config::builder()
        .appender(Appender::builder().build(CONSOLE_APPENDER, Box::new(build_console())))
        .logger(Logger::builder().build(DEFAULT_LOGGER.0, DEFAULT_LOGGER.1))
}

fn build(builder: ConfigBuilder) -> Config {
    builder
        .build(Root::builder().appender(CONSOLE_APPENDER).build(ROOT_LEVEL))
        .expect("valid log4rs config")
}

fn add_file_logger(
    mut builder: ConfigBuilder,
    appender_name: &str,
    logger_name: &str,
    path: &Path,
    rollover_size_bytes: u64,
    rollover_count: u32,
) -> ConfigBuilder {
    let Some(appender) = build_rolling_file(path, rollover_size_bytes, rollover_count) else {
        warn!("unable to build rolling file appender properly");
        return builder;
    };

    builder = builder.appender(Appender::builder().build(appender_name, Box::new(appender)));

    builder.logger(
        Logger::builder()
            .appender(appender_name)
            .additive(false) // domain logs go ONLY to their file appender
            .build(logger_name, LevelFilter::Info),
    )
}

pub fn init() {
    let config = build(base_builder());
    let handle = log4rs::init_config(config).expect("log4rs init");
    let _ = HANDLE.set(handle);
}

/// Add rolling-file appenders for each domain log.
/// Call after YAML config is parsed so paths are known.
///
/// rollover_count = number of archived copies to keep per appender.
pub fn add_file_appenders(
    firewall: Option<&Path>,
    process: Option<&Path>,
    ace: Option<&Path>,
    yara: Option<&Path>,
    scan: Option<&Path>,
    rollover_size_bytes: u64,
    rollover_count: u32,
) {
    let Some(handle) = HANDLE.get() else {
        // init() was never called; nothing to update.
        return;
    };

    let mut builder = base_builder();

    if let Some(path) = firewall {
        builder = add_file_logger(
            builder,
            "firewall_file",
            "rb2_firewall",
            path,
            rollover_size_bytes,
            rollover_count,
        );
    }

    if let Some(path) = process {
        builder = add_file_logger(
            builder,
            "process_file",
            "rb2_process",
            path,
            rollover_size_bytes,
            rollover_count,
        );
    }

    if let Some(path) = ace {
        builder = add_file_logger(
            builder,
            "ace_file",
            "rb2_ace",
            path,
            rollover_size_bytes,
            rollover_count,
        );
    }

    if let Some(path) = yara {
        builder = add_file_logger(
            builder,
            "yara_file",
            "rb2_yara",
            path,
            rollover_size_bytes,
            rollover_count,
        );
    }

    if let Some(path) = scan {
        builder = add_file_logger(
            builder,
            "scan_file",
            "rb2_scan",
            path,
            rollover_size_bytes,
            rollover_count,
        );
    }

    handle.set_config(build(builder));
}
