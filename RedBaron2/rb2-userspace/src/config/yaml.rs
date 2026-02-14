use anyhow::{Context, Result, bail};
use log::{debug, error, info, warn};
use once_cell::sync::OnceCell;
use std::{
    collections::HashSet,
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use yaml_rust2::YamlLoader;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub log_file: PathBuf,
    pub poll_interval_secs: Option<u64>,
}

/// Execution order: alert -> collect sample -> kill.
#[derive(Debug, Clone, PartialEq)]
pub struct YaraActions {
    pub alert: bool,
    /// Send SIGKILL
    pub kill: bool,
    /// strip ELF header & save to `samples_dir`
    pub move_sample: bool,
    /// Upload the unstripped binary sample to S3 (independent of `move_sample`).
    pub forward_to_s3: bool,
}

#[derive(Debug, Clone)]
pub struct YaraConfig {
    pub rules_dir: Option<PathBuf>,
    pub log_file: PathBuf,
    pub max_scan_bytes_per_rule: Option<u64>,
    pub poll_interval_secs: Option<u64>,
    pub full_scan_interval_secs: Option<u64>,
    pub disabled_rules: HashSet<String>,
    pub disable_bundled_rules: bool,
    pub actions: YaraActions,
    pub samples_dir: PathBuf,
    pub fanotify_enabled: bool,
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
}

#[derive(Debug, Clone, PartialEq)]
pub enum HandlerConfig {
    Kill,
    Nfq,
}

#[derive(Debug, Clone)]
pub struct ProcessConfig {
    pub rhai_enabled: bool,
    /// Optional directory of extra YAML rules; loaded at startup only.
    pub rhai_rules_dir: Option<PathBuf>,
    pub log_file: PathBuf,
    pub alert_log_file: PathBuf,
    pub disabled_rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TtyStorage {
    Files,
    Sqlite,
}

#[derive(Debug, Clone)]
pub struct TTYConfig {
    pub encrypt: bool,
    pub authorized_keys_path: Option<PathBuf>,
    pub pubkey: Option<String>,
    pub flush_interval_secs: u64,
    pub storage: TtyStorage,
    pub sqlite_path: PathBuf,
    pub sqlite_max_size_mb: u64,
    pub forward_to_s3: bool,
    pub s3_forward_interval_secs: u64,
}

#[derive(Debug, Clone)]
pub struct ObjectStorageConfig {
    pub endpoint: String,
    pub bucket_tty: String,
    pub bucket_samples: Option<String>,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub path_style: bool,
}

#[derive(Debug, Clone)]
pub struct OpenObserveConfig {
    pub url: String,
    pub org: String,
    pub stream_prefix: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct IngestorConfig {
    pub ingestor_type: String,
    pub poll_interval_secs: u64,
    pub log_rollover_size_mb: u64,
    pub stats_interval_secs: u64,
    pub openobserve: Option<OpenObserveConfig>,
}

#[derive(Debug, Clone)]
pub struct FeaturesConfig {
    pub firewall: bool,
    pub process: bool,
    pub yara: bool,
    pub scan: bool,
    pub ingestor: bool,
    pub tty: bool,
}

#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub log_dir: PathBuf,
    pub rollover_size_bytes: u64,
    /// Number of archived log files to keep per appender
    pub rollover_count: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("/var/log/rb2"),
            rollover_size_bytes: 10 * 1024 * 1024, // 10 MB
            rollover_count: 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub yara: Option<YaraConfig>,
    pub firewall: Option<FirewallConfig>,
    pub process: Option<ProcessConfig>,
    pub scan: Option<ScanConfig>,
    pub tty: Option<TTYConfig>,
    pub ingestor: Option<IngestorConfig>,
    pub object_storage: Option<ObjectStorageConfig>,
    pub logging: LoggingConfig,
}

static CONFIG: OnceCell<AppConfig> = OnceCell::new();

pub fn get_config() -> Result<&'static AppConfig> {
    CONFIG.get_or_try_init(init_from_env)
}

pub fn init_from_env() -> Result<AppConfig> {
    const DEFAULT_PATH: &str = "/etc/rb2.yaml";

    let path = match env::var("RB2_CONFIG") {
        Ok(p) => p,
        Err(_) => {
            if Path::new(DEFAULT_PATH).exists() {
                info!(
                    "RB2_CONFIG not set; using default config at {}",
                    DEFAULT_PATH
                );
                DEFAULT_PATH.to_string()
            } else {
                bail!(
                    "RB2_CONFIG env var not set and default config not found at {}",
                    DEFAULT_PATH
                );
            }
        }
    };

    let content =
        fs::read_to_string(&path).with_context(|| format!("Failed to read config {}", path))?;

    parse_config_from_str(&content).with_context(|| format!("Config parse failed for {}", path))
}

/// Parse the last ed25519 public key from an authorized_keys file.
/// Returns None if the file doesn't exist, is unreadable, or contains no ed25519 keys.
fn parse_last_ed25519_key(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let mut lines = content.lines().filter(|line| {
        let trimmed = line.trim();
        !trimmed.is_empty() && !trimmed.starts_with('#') && trimmed.starts_with("ssh-ed25519 ")
    });
    lines.next_back().map(|s| s.to_string())
}

/// Get the default authorized_keys path for the current user.
fn default_authorized_keys_path() -> Option<PathBuf> {
    env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".ssh").join("authorized_keys"))
}

fn parse_config_from_str(yaml: &str) -> Result<AppConfig> {
    let docs = YamlLoader::load_from_str(yaml).context("Failed to parse YAML")?;
    let doc = docs
        .first()
        .ok_or_else(|| anyhow::anyhow!("Empty YAML config"))?;

    // features (default-on if omitted)
    let features = FeaturesConfig {
        firewall: doc["features"]["firewall"].as_bool().unwrap_or(true),
        process: doc["features"]["process"].as_bool().unwrap_or(true),
        yara: doc["features"]["yara"].as_bool().unwrap_or(true),
        scan: doc["features"]["scan"].as_bool().unwrap_or(true),
        tty: doc["features"]["tty"].as_bool().unwrap_or(true),
        ingestor: doc["features"]["ingestor"].as_bool().unwrap_or(false),
    };

    // logging (optional, all fields have sane defaults) — parsed early so
    // log_dir is available for the feature sections that derive log paths.
    let logging = {
        let default = LoggingConfig::default();

        let log_dir = doc["logging"]["log_dir"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| default.log_dir.clone());

        let rollover_size_bytes = doc["logging"]["rollover_size_mb"]
            .as_i64()
            .map(|mb| mb as u64 * 1024 * 1024)
            .unwrap_or(default.rollover_size_bytes);

        let rollover_count = doc["logging"]["rollover_count"]
            .as_i64()
            .map(|v| v as u32)
            .unwrap_or(default.rollover_count);

        if !log_dir.exists() {
            if let Err(e) = fs::create_dir_all(&log_dir) {
                error!("Failed to create log dir {:?}: {}", log_dir, e);
            }

            if let Err(e) = fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700)) {
                error!("Failed to chmod 0700 on log dir {:?}: {}", log_dir, e);
            }
        }

        LoggingConfig {
            log_dir,
            rollover_size_bytes,
            rollover_count,
        }
    };

    let log_dir = &logging.log_dir;

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

        let disabled_rules: HashSet<String> = doc["yara"]["disabled_rules"]
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

        let actions = {
            let raw: Vec<String> = doc["yara"]["actions"]
                .as_vec()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                        .collect()
                })
                .unwrap_or_else(|| ["kill".to_string()].into());

            let mut kill = false;
            let mut move_sample = false;
            let mut forward_to_s3 = false;
            for item in &raw {
                match item.as_str() {
                    "kill" => kill = true,
                    "move" => move_sample = true,
                    "forward_to_s3" => forward_to_s3 = true,
                    other => {
                        warn!("Unknown yara.actions entry '{}', ignoring", other);
                    }
                }
            }

            YaraActions {
                alert: true, // always alert
                kill,
                move_sample,
                forward_to_s3,
            }
        };

        let samples_dir = doc["yara"]["samples_dir"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/rb2/samples"));

        let fanotify_enabled = doc["yara"]["fanotify_enabled"].as_bool().unwrap_or(true);

        Some(YaraConfig {
            rules_dir,
            log_file: log_dir.join("yara"),
            max_scan_bytes_per_rule,
            poll_interval_secs,
            full_scan_interval_secs,
            disabled_rules,
            disable_bundled_rules,
            actions,
            samples_dir,
            fanotify_enabled,
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
        let rhai_enabled = doc["process"]["rhai_enabled"].as_bool().unwrap_or(true);

        let rhai_rules_dir = doc["process"]["rhai_rules_dir"].as_str().map(PathBuf::from);

        let disabled_rules: Vec<String> = doc["process"]["disabled_rules"]
            .as_vec()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Some(ProcessConfig {
            rhai_enabled,
            rhai_rules_dir,
            log_file: log_dir.join("process"),
            alert_log_file: log_dir.join("alert"),
            disabled_rules,
        })
    } else {
        None
    };

    // scan
    let scan = if features.scan {
        let poll_interval_secs = doc["scan"]["poll_interval_secs"].as_i64().map(|v| v as u64);
        Some(ScanConfig {
            log_file: log_dir.join("scan"),
            poll_interval_secs,
        })
    } else {
        None
    };

    // tty
    let tty = if features.tty {
        let encrypt = doc["tty"]["encrypt"].as_bool().unwrap_or(true);

        let flush_interval_secs = doc["tty"]["flush_interval_secs"]
            .as_i64()
            .map(|v| v as u64)
            .unwrap_or(10);

        let storage = match doc["tty"]["storage"].as_str().unwrap_or("files") {
            "sqlite" => TtyStorage::Sqlite,
            _ => TtyStorage::Files,
        };

        let sqlite_path = doc["tty"]["sqlite_path"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/rb2/tty_sessions.db"));

        let sqlite_max_size_mb = doc["tty"]["sqlite_max_size_mb"]
            .as_i64()
            .map(|v| v as u64)
            .unwrap_or(256);

        let forward_to_s3 = doc["tty"]["forward_to_s3"].as_bool().unwrap_or(false);
        let s3_forward_interval_secs = doc["tty"]["s3_forward_interval_secs"]
            .as_i64()
            .map(|v| v as u64)
            .unwrap_or(60);

        let authorized_keys_path = doc["tty"]["authorized_keys"]
            .as_str()
            .map(|s| {
                if s.starts_with("~/") {
                    env::var("HOME")
                        .ok()
                        .map(|home| PathBuf::from(home).join(&s[2..]))
                        .unwrap_or_else(|| PathBuf::from(s))
                } else {
                    PathBuf::from(s)
                }
            })
            .or_else(default_authorized_keys_path);

        if encrypt {
            let pubkey = authorized_keys_path
                .as_ref()
                .and_then(|path| parse_last_ed25519_key(path));

            match &pubkey {
                Some(key) => {
                    debug!(
                        "TTY encryption enabled with ed25519 key from {:?}",
                        authorized_keys_path
                    );
                    Some(TTYConfig {
                        encrypt: true,
                        authorized_keys_path,
                        pubkey: Some(key.clone()),
                        flush_interval_secs,
                        storage,
                        sqlite_path,
                        sqlite_max_size_mb,
                        forward_to_s3,
                        s3_forward_interval_secs,
                    })
                }
                None => {
                    error!(
                        "TTY encryption is enabled but no valid ed25519 key found in {:?}. \
                         TTY session recording has been disabled. \
                         Either add an ssh-ed25519 key to your authorized_keys file, \
                         or set tty.encrypt: false in the config.",
                        authorized_keys_path
                    );
                    None
                }
            }
        } else {
            debug!("TTY encryption disabled, session recordings will not be encrypted");
            Some(TTYConfig {
                encrypt: false,
                authorized_keys_path,
                pubkey: None,
                flush_interval_secs,
                storage,
                sqlite_path,
                sqlite_max_size_mb,
                forward_to_s3,
                s3_forward_interval_secs,
            })
        }
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

        let stats_interval_secs = doc["ingestor"]["stats_interval_secs"]
            .as_i64()
            .map(|v| v as u64)
            .unwrap_or(120);

        let openobserve = if ingestor_type == "openobserve" {
            let oo_doc = &doc["ingestor"]["openobserve"];
            Some(OpenObserveConfig {
                url: oo_doc["url"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("ingestor.openobserve.url missing"))?
                    .to_string(),
                org: oo_doc["org"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("ingestor.openobserve.org missing"))?
                    .to_string(),
                stream_prefix: oo_doc["stream_prefix"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("ingestor.openobserve.stream_prefix missing"))?
                    .to_string(),
                username: oo_doc["username"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("ingestor.openobserve.username missing"))?
                    .to_string(),
                password: oo_doc["password"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("ingestor.openobserve.password missing"))?
                    .to_string(),
            })
        } else {
            None
        };

        Some(IngestorConfig {
            ingestor_type,
            poll_interval_secs,
            log_rollover_size_mb,
            stats_interval_secs,
            openobserve,
        })
    } else {
        None
    };

    // object_storage (top-level, optional — needed when TTY S3 forwarding
    // or YARA sample S3 forwarding is enabled)
    let needs_object_storage = tty.as_ref().is_some_and(|t| t.forward_to_s3)
        || yara.as_ref().is_some_and(|y| y.actions.forward_to_s3);
    let object_storage = if needs_object_storage && !doc["object_storage"]["endpoint"].is_badvalue()
    {
        let os_doc = &doc["object_storage"];
        Some(ObjectStorageConfig {
            endpoint: os_doc["endpoint"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("object_storage.endpoint missing"))?
                .to_string(),
            bucket_tty: os_doc["bucket_tty"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("object_storage.bucket_tty missing"))?
                .to_string(),
            bucket_samples: os_doc["bucket_samples"].as_str().map(String::from),
            region: os_doc["region"].as_str().unwrap_or("us-east-1").to_string(),
            access_key: os_doc["access_key"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("object_storage.access_key missing"))?
                .to_string(),
            secret_key: os_doc["secret_key"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("object_storage.secret_key missing"))?
                .to_string(),
            path_style: os_doc["path_style"].as_bool().unwrap_or(true),
        })
    } else {
        None
    };

    Ok(AppConfig {
        yara,
        firewall,
        process,
        scan,
        tty,
        ingestor,
        object_storage,
        logging,
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

    #[test]
    fn parse_full_user_config() {
        let yaml = r#"
features:
  firewall: true
  yara: true
  process: true
  tty: true
  scan: true
  ingestor: true

firewall:
  enforcing: false
  producer: ebpf
  handler: kill
  binary_whitelist:
    - /snap/amazon-ssm-agent/12322/ssm-agent-worker
    - /usr/bin/docker-proxy
    - /usr/lib/systemd/systemd
    - /usr/lib/systemd/systemd-networkd
    - /usr/lib/systemd/systemd-resolved
    - /usr/sbin/chronyd
    - /usr/sbin/sshd
    - /usr/bin/sudo
    - /home/ubuntu/rb2

yara:
  rules_dir: # /var/lib/rb2/yara # optional for extra rules
  disable_bundled_rules: false
  disabled_rules: # optional
  #   - Multi_EICAR
  actions:
    - kill
    # - move
    - forward_to_s3
  samples_dir: /var/lib/rb2/samples

tty:
  encrypt: true
  authorized_keys: /root/.ssh/authorized_keys
  flush_interval_secs: 10
  storage: sqlite
  sqlite_path: /var/lib/rb2/tty_sessions.db
  sqlite_max_size_mb: 256
  forward_to_s3: false
  s3_forward_interval_secs: 60

ingestor:
  type: openobserve
  poll_interval_secs: 5
  log_rollover_size_mb: 10
  openobserve:
    url: http://34.203.208.139:5080
    org: default
    stream_prefix: rb2-logs
    username: root@example.com
    password: TinyStoveWingMugIckyPlanner

object_storage:
   endpoint: "http://127.0.0.1:9000"
   bucket_tty: "rb2-tty"
   bucket_samples: "rb2-samples"
   region: "us-east-1"
   access_key: "fakeaccesskey"
   secret_key: "fakesecretkey"
   path_style: true

logging:
  log_dir: /var/log/rb2
  rollover_size_mb: 10
  rollover_count: 5

process:
  rhai_enabled: true
  disabled_rules:
"#;
        let cfg = parse_config_from_str(yaml).expect("parse ok");
        assert!(cfg.yara.is_some());
        let yara = cfg.yara.unwrap();
        assert!(yara.actions.alert);
        assert!(yara.actions.kill);
        assert!(!yara.actions.move_sample);
        assert!(yara.actions.forward_to_s3);
        assert!(cfg.object_storage.is_some());
        let os = cfg.object_storage.unwrap();
        assert_eq!(os.bucket_samples.as_deref(), Some("rb2-samples"));
    }
}
