use log::{debug, error, warn};
use once_cell::sync::OnceCell;
use std::{collections::HashSet, convert::From, env, fs, path::PathBuf};
use yaml_rust2::YamlLoader;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub log_file: PathBuf,
    pub poll_interval_secs: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct YaraConfig {
    pub rules_dir: Option<PathBuf>,
    pub log_file: PathBuf,
    pub max_scan_bytes_per_rule: Option<u64>,
    pub poll_interval_secs: Option<u64>,
    pub full_scan_interval_secs: Option<u64>,
    pub disabled_rules: Vec<String>,
    pub disable_bundled_rules: bool,
}

#[derive(Debug, Clone)]
pub struct FirewallConfig {
    pub binary_whitelist: HashSet<PathBuf>,
    pub log_file: PathBuf,
    pub enforcing: bool,

    pub producer: ProducerConfig,
    pub handler: HandlerConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProducerConfig {
    Ebpf,
    Nfq,
    Auditd,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HandlerConfig {
    Kill,
    Nfq,
}

#[derive(Debug, Clone)]
pub struct ProcessConfig {
    pub rhai_rules_dir: PathBuf,
    pub log_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct OpenObserveConfig {
    pub url: String,
    pub org: String,
    pub stream: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct IngestorConfig {
    pub ingestor_type: String,
    pub poll_interval_secs: u64,
    pub log_rollover_size_mb: u64,
    pub openobserve: Option<OpenObserveConfig>,
}

#[derive(Debug, Clone)]
pub struct FeaturesConfig {
    pub firewall: bool,
    pub process: bool,
    pub yara: bool,
    pub scan: bool,
    pub ingestor: bool,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub yara: Option<YaraConfig>,
    pub firewall: Option<FirewallConfig>,
    pub process: Option<ProcessConfig>,
    pub scan: Option<ScanConfig>,
    pub ingestor: Option<IngestorConfig>,
}

static CONFIG: OnceCell<AppConfig> = OnceCell::new();

/// panics if the config isn't already set up or initializable from environment variable
pub fn get_config() -> Result<&'static AppConfig, String> {
    CONFIG.get_or_try_init(init_from_env)
}

pub fn init_from_env() -> Result<AppConfig, String> {
    let path = env::var("RB2_CONFIG").map_err(|_| "RB2_CONFIG env var not set".to_string())?;

    let content =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read config {path}: {e}"))?;

    parse_config_from_str(&content)
}

fn parse_config_from_str(yaml: &str) -> Result<AppConfig, String> {
    let docs = YamlLoader::load_from_str(yaml).map_err(|e| format!("Failed to parse YAML: {e}"))?;
    let doc = docs
        .first()
        .ok_or_else(|| "Empty YAML config".to_string())?;

    // features (default-on if omitted)
    let features = FeaturesConfig {
        firewall: doc["features"]["firewall"].as_bool().unwrap_or(true),
        process: doc["features"]["process"].as_bool().unwrap_or(true),
        yara: doc["features"]["yara"].as_bool().unwrap_or(true),
        scan: doc["features"]["scan"].as_bool().unwrap_or(true),
        ingestor: doc["features"]["ingestor"].as_bool().unwrap_or(false),
    };

    let log_dir = doc["log_dir"]
        .as_str()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/log/rb2"));
    if !log_dir.exists()
        && let Err(e) = fs::create_dir_all(&log_dir)
    {
        error!("Failed to create log dir {:?}: {}", log_dir, e);
    }

    // yara
    let yara = if features.yara {
        let rules_dir = doc["yara"]["rules_dir"].as_str().map(PathBuf::from);

        let max_scan_bytes_per_rule = doc["yara"]["max_scan_bytes_per_rule"]
            .as_i64()
            .map(|v| v as u64);

        let poll_interval_secs = doc["yara"]["poll_interval_secs"].as_i64().map(|v| v as u64);

        let full_scan_interval_secs = doc["yara"]["full_scan_interval_secs"]
            .as_i64()
            .map(|v| v as u64);

        let disabled_rules: Vec<String> = doc["yara"]["disabled_rules"]
            .as_vec()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let disable_bundled_rules = doc["yara"]["disable_bundled_rules"]
            .as_bool()
            .unwrap_or(false);

        Some(YaraConfig {
            rules_dir,
            log_file: log_dir.join("yara"),
            max_scan_bytes_per_rule,
            poll_interval_secs,
            full_scan_interval_secs,
            disabled_rules,
            disable_bundled_rules,
        })
    } else {
        None
    };

    // firewall
    let firewall = if features.firewall {
        let binary_whitelist: HashSet<PathBuf> = doc["firewall"]["binary_whitelist"]
            .as_vec()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(PathBuf::from))
                    .collect::<Vec<PathBuf>>()
            })
            .unwrap_or_default()
            .into_iter()
            .collect();

        let enforcing = doc["firewall"]["enforcing"].as_bool().unwrap_or(false);

        let mut producer = match doc["firewall"]["producer"].as_str().unwrap_or("ebpf") {
            "nfq" => ProducerConfig::Nfq,
            "ebpf" => ProducerConfig::Ebpf,
            "auditd" => ProducerConfig::Auditd,
            other => {
                warn!(
                    "Unknown firewall producer type '{}', falling back to nfq",
                    other
                );
                ProducerConfig::Nfq
            }
        };

        let mut handler = match doc["firewall"]["handler"].as_str().unwrap_or("kill") {
            "nfq" => HandlerConfig::Nfq,
            "kill" => HandlerConfig::Kill,
            other => {
                warn!(
                    "Unknown firewall handler type '{}', falling back to kill",
                    other
                );
                HandlerConfig::Nfq
            }
        };

        if (producer == ProducerConfig::Nfq) && (handler != HandlerConfig::Nfq) {
            warn!(
                "Firewall producer is of type nfq, but handler {:?} is not. Making handler also nfq",
                handler
            );
            handler = HandlerConfig::Nfq;
        } else if (producer != ProducerConfig::Nfq) && (handler == HandlerConfig::Nfq) {
            warn!(
                "Firewall handler is of type nfq, but producer {:?} is not. Making producer also nfq",
                producer
            );
            producer = ProducerConfig::Nfq;
        }

        debug!(
            "Firewall producer {:?} Firewall handler {:?}",
            producer, handler
        );

        Some(FirewallConfig {
            binary_whitelist,
            log_file: log_dir.join("firewall"),
            enforcing,
            producer,
            handler,
        })
    } else {
        None
    };

    // process
    let process = if features.process {
        let rhai_rules_dir = doc["process"]["rhai_rules_dir"]
            .as_str()
            .map(PathBuf::from)
            .ok_or_else(|| "process.rhai_rules_dir missing".to_string())?;

        Some(ProcessConfig {
            rhai_rules_dir,
            log_file: log_dir.join("process"),
        })
    } else {
        None
    };

    let scan = if features.scan {
        let poll_interval_secs = doc["scan"]["poll_interval_secs"].as_i64().map(|v| v as u64);
        Some(ScanConfig {
            log_file: log_dir.join("scan"),
            poll_interval_secs,
        })
    } else {
        None
    };

    // ingestor
    let ingestor = if features.ingestor {
        let ingestor_type = doc["ingestor"]["type"]
            .as_str()
            .unwrap_or("openobserve")
            .to_string();

        let poll_interval_secs = doc["ingestor"]["poll_interval_secs"]
            .as_i64()
            .map(|v| v as u64)
            .unwrap_or(2);

        let log_rollover_size_mb = doc["ingestor"]["log_rollover_size_mb"]
            .as_i64()
            .map(|v| v as u64)
            .unwrap_or(10);

        let openobserve = if ingestor_type == "openobserve" {
            let oo_doc = &doc["ingestor"]["openobserve"];
            Some(OpenObserveConfig {
                url: oo_doc["url"]
                    .as_str()
                    .ok_or_else(|| "ingestor.openobserve.url missing".to_string())?
                    .to_string(),
                org: oo_doc["org"]
                    .as_str()
                    .ok_or_else(|| "ingestor.openobserve.org missing".to_string())?
                    .to_string(),
                stream: oo_doc["stream"]
                    .as_str()
                    .ok_or_else(|| "ingestor.openobserve.stream missing".to_string())?
                    .to_string(),
                username: oo_doc["username"]
                    .as_str()
                    .ok_or_else(|| "ingestor.openobserve.username missing".to_string())?
                    .to_string(),
                password: oo_doc["password"]
                    .as_str()
                    .ok_or_else(|| "ingestor.openobserve.password missing".to_string())?
                    .to_string(),
            })
        } else {
            None
        };

        Some(IngestorConfig {
            ingestor_type,
            poll_interval_secs,
            log_rollover_size_mb,
            openobserve,
        })
    } else {
        None
    };

    Ok(AppConfig {
        yara,
        firewall,
        process,
        scan,
        ingestor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() {
        let yaml = r#"
features: { firewall: true, process: true, yara: true }
yara: { rules_dir: "/tmp/rules" }
firewall: { binary_whitelist: ["/bin/ls"] }
process: { rhai_rules_dir: "/tmp/rhai" }
"#;
        let cfg = parse_config_from_str(yaml).expect("parse ok");
        assert!(cfg.yara.is_some());
        assert!(cfg.firewall.is_some());
        assert!(cfg.process.is_some());
        assert!(cfg.ingestor.is_none());
    }

    #[test]
    fn disabled_features_are_none() {
        let yaml = r#"
features: { firewall: false, process: false, yara: false, ingestor: false }
"#;
        let cfg = parse_config_from_str(yaml).expect("parse ok");
        assert!(cfg.yara.is_none());
        assert!(cfg.firewall.is_none());
        assert!(cfg.process.is_none());
        assert!(cfg.ingestor.is_none());
    }

    #[test]
    fn yara_rules_dir_optional() {
        let yaml = r#"
features: { firewall: false, process: false, yara: true }
yara: {}
"#;
        let cfg = parse_config_from_str(yaml).expect("parse ok");
        assert!(cfg.yara.is_some());
        assert!(cfg.yara.unwrap().rules_dir.is_none());
    }
}
