pub mod fanotify;
mod helper;
pub mod s3_samples;
pub mod yara_scan;

pub(crate) use helper::handle_yara_match;

use self::fanotify::yara_init_fanotify_scan;
use self::yara_scan::yara_init_memory_scan;

use crate::config::yaml::YaraConfig;

use anyhow::Context;
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::{
    fs::{self},
    io::Read,
    path::PathBuf,
    thread,
};
use yara_x::{Compiler, Rules};

pub fn build_rules(
    disable_bundled_rules: bool,
    rules_dir: &Option<PathBuf>,
) -> anyhow::Result<Rules> {
    let mut compiler = Compiler::new();

    // bundled rules
    if !disable_bundled_rules {
        const EMBEDDED_RULES_COMPRESSED: &[u8] =
            include_bytes!(concat!(env!("OUT_DIR"), "/compiled_yara_rules.xz"));

        debug!("Loading and decompressing embedded YARA rules from build");

        let mut decoder = xz2::read::XzDecoder::new(EMBEDDED_RULES_COMPRESSED);
        let mut embedded_rules = String::new();
        decoder
            .read_to_string(&mut embedded_rules)
            .context("Failed to decompress embedded YARA rules")?;

        if !embedded_rules.is_empty() {
            compiler.add_source(embedded_rules.as_str())?;
        } else {
            info!("No embedded YARA rules found in binary");
        }
    } else {
        info!("Bundled YARA rules disabled via config");
    }

    // extra rules
    if let Some(dir) = rules_dir {
        if dir.exists() {
            info!("Loading additional YARA rules from: {}", dir.display());
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if let Some(ext) = path.extension().and_then(|s| s.to_str())
                    && (ext == "yara" || ext == "yar")
                {
                    let source = fs::read_to_string(&path)?;
                    compiler.add_source(source.as_str())?;
                }
            }
        } else {
            warn!("Rules directory {} does not exist, skipping", dir.display());
        }
    }

    if rules_dir.is_none() && disable_bundled_rules {
        Err(anyhow::anyhow!("No yara rules provided to scan"))
    } else {
        Ok(compiler.build())
    }
}

pub fn yara_init_scan(cfg: &YaraConfig) -> anyhow::Result<()> {
    let rules = build_rules(cfg.disable_bundled_rules, &cfg.rules_dir)?;
    let rules = Arc::new(rules);
    {
        let rules = rules.clone();
        let cfg = cfg.clone();
        thread::spawn(move || {
            const YARA_NICE_LEVEL: i32 = 10;
            unsafe { libc::nice(YARA_NICE_LEVEL) };
            let actual_nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
            info!(
                "YARA scanning thread running with nice level {}",
                actual_nice
            );

            if let Err(e) = yara_init_memory_scan(&cfg, &rules) {
                error!("YARA memory scanning failed: {}", e);
            }
        });
    }
    {
        if cfg.fanotify_enabled {
            let rules = rules.clone();
            let cfg = cfg.clone();
            thread::spawn(move || {
                if let Err(e) = yara_init_fanotify_scan(&cfg, &rules) {
                    error!("YARA fanotify scanning failed: {}", e);
                }
            });
        } else {
            info!("Fanotify disabled by config");
        }
    }

    Ok(())
}
