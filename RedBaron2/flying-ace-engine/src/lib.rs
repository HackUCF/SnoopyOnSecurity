// src/lib.rs - full file
use regex::Regex;
use rhai::ImmutableString;
use rhai::{AST, Dynamic, Engine, Scope};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::{fmt, fs, path::Path};

// -----------------------------------------------------------------------------
// Rule mode: alert (log only) or kill (terminate + log).  Defaults to Alert.
// -----------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    #[default]
    Alert,
    Kill,
}

impl fmt::Display for RuleMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleMode::Alert => write!(f, "alert"),
            RuleMode::Kill => write!(f, "kill"),
        }
    }
}

/// Returned by the engine for every rule that fires on a given event.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub name: String,
    pub mode: RuleMode,
}

// -----------------------------------------------------------------------------
// ECS‑compatible event struct (minimal subset – extend as needed)
// -----------------------------------------------------------------------------
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProcessEvent {
    pub timestamp: String,

    // process.*
    pub process_name: String,
    pub process_pid: u32,
    pub process_sid: u32,
    pub process_args: Option<String>,
    pub process_executable: Option<String>,
    pub process_ppid: Option<u32>,
    pub process_pname: Option<String>, // parent name
    pub process_working_directory: Option<String>,

    // user.*
    pub user_name: Option<String>,
    pub user_id: Option<u32>,

    // event.*
    pub event_category: String,
    pub event_module: Option<String>,
    pub ecs_version: String,

    // host.*
    pub host_name: Option<String>,
    pub host_id: Option<String>,
}

impl fmt::Display for ProcessEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = if f.alternate() {
            serde_json::to_string_pretty(self)
        } else {
            serde_json::to_string(self)
        }
        .map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}

// -----------------------------------------------------------------------------
// Push nested ECS objects into a Rhai Scope
// -----------------------------------------------------------------------------
impl ProcessEvent {
    pub fn to_scope(&self) -> Scope<'_> {
        let mut scope = Scope::new();

        scope.push("e", self.clone());

        scope
    }

    fn get_timestamp(&mut self) -> Dynamic {
        self.timestamp.clone().into()
    }
    fn get_ecs_version(&mut self) -> Dynamic {
        self.ecs_version.clone().into()
    }
    fn get_event_category(&mut self) -> Dynamic {
        self.event_category.clone().into()
    }
    fn get_event_module(&mut self) -> Dynamic {
        self.event_module
            .clone()
            .map(Into::into)
            .unwrap_or(Dynamic::UNIT)
    }
    // process.*
    fn get_process_name(&mut self) -> ImmutableString {
        self.process_name.clone().into()
    }
    fn get_process_pid(&mut self) -> i64 {
        self.process_pid as i64
    }
    fn get_process_sid(&mut self) -> i64 {
        self.process_sid as i64
    }
    fn get_process_args(&mut self) -> Dynamic {
        self.process_args
            .clone()
            .map(Into::into)
            .unwrap_or(Dynamic::UNIT)
    }
    fn get_process_executable(&mut self) -> Dynamic {
        self.process_executable
            .clone()
            .map(Into::into)
            .unwrap_or(Dynamic::UNIT)
    }
    fn get_process_ppid(&mut self) -> i64 {
        if let Some(pid) = self.process_ppid {
            pid as i64
        } else {
            -1
        }
    }
    fn get_process_pname(&mut self) -> Dynamic {
        self.process_pname
            .clone()
            .map(Into::into)
            .unwrap_or(Dynamic::UNIT)
    }
    fn get_process_working_directory(&mut self) -> Dynamic {
        self.process_working_directory
            .clone()
            .map(Into::into)
            .unwrap_or(Dynamic::UNIT)
    }

    // host.*
    fn get_host_name(&mut self) -> Dynamic {
        self.host_name
            .clone()
            .map(Into::into)
            .unwrap_or(Dynamic::UNIT)
    }
    fn get_host_id(&mut self) -> Dynamic {
        self.host_id
            .clone()
            .map(Into::into)
            .unwrap_or(Dynamic::UNIT)
    }

    // user.*
    fn get_user_name(&mut self) -> Dynamic {
        self.user_name
            .clone()
            .map(Into::into)
            .unwrap_or(Dynamic::UNIT)
    }
    fn get_user_id(&mut self) -> i64 {
        if let Some(uid) = self.user_id {
            uid as i64
        } else {
            -1
        }
    }
}

// -----------------------------------------------------------------------------
// YAML rule representation
// -----------------------------------------------------------------------------
#[derive(Debug, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub mode: RuleMode,
    pub eval: String,
    // `tests` is only used by the test harness; ignored at runtime.
}

#[derive(Debug)]
struct CompiledRule {
    name: String,
    mode: RuleMode,
    ast: AST,
}

// -----------------------------------------------------------------------------
// Rhai Engine wrapper
// -----------------------------------------------------------------------------
pub struct EcsRhaiEngine {
    engine: Engine,
    rules: Vec<CompiledRule>,
}

impl EcsRhaiEngine {
    /// Create a new Rhai engine with all custom functions and type registrations.
    fn new_engine() -> Engine {
        let mut engine = Engine::new();
        engine.set_optimization_level(rhai::OptimizationLevel::Full);
        engine.set_fast_operators(true);
        engine.set_allow_loop_expressions(false);
        engine.set_allow_switch_expression(false);

        // add in custom functions to rhai language
        // XXX: may want to implement cache for pre-compiled regex rules
        engine.register_fn("re_match", |text: Dynamic, pattern: &str| -> bool {
            let text = text.to_string();
            match Regex::new(pattern) {
                Ok(re) => re.is_match(&text),
                Err(_) => false,
            }
        });

        engine
            .register_type::<ProcessEvent>()
            // top-level
            .register_get("timestamp", ProcessEvent::get_timestamp)
            // process.*
            .register_get("process_name", ProcessEvent::get_process_name)
            .register_get("process_pid", ProcessEvent::get_process_pid)
            .register_get("process_sid", ProcessEvent::get_process_sid)
            .register_get("process_args", ProcessEvent::get_process_args)
            .register_get("process_executable", ProcessEvent::get_process_executable)
            .register_get("process_ppid", ProcessEvent::get_process_ppid)
            .register_get("process_pname", ProcessEvent::get_process_pname)
            .register_get(
                "process_working_directory",
                ProcessEvent::get_process_working_directory,
            )
            // user.*
            .register_get("user_name", ProcessEvent::get_user_name)
            .register_get("user_id", ProcessEvent::get_user_id)
            // event.*
            .register_get("event_category", ProcessEvent::get_event_category)
            .register_get("event_module", ProcessEvent::get_event_module)
            .register_get("ecs_version", ProcessEvent::get_ecs_version)
            // host.*
            .register_get("host_name", ProcessEvent::get_host_name)
            .register_get("host_id", ProcessEvent::get_host_id);

        engine
    }

    /// Try to compile a [`Rule`] and push it onto the compiled rules vec.
    /// Returns `true` if the rule was added, `false` if skipped or failed.
    /// if override_mode is enabled, the rules won't be able to enforce, only alert
    fn try_add_rule(
        engine: &Engine,
        rules: &mut Vec<CompiledRule>,
        rule: Rule,
        override_mode: bool,
    ) -> bool {
        match engine.compile(&rule.eval) {
            Ok(ast) => {
                rules.push(CompiledRule {
                    name: rule.name,
                    mode: if override_mode {
                        RuleMode::Alert
                    } else {
                        rule.mode
                    },
                    ast,
                });
                true
            }
            Err(err) => {
                eprintln!("Failed to compile rule '{}': {err}", rule.name);
                false
            }
        }
    }

    /// Load rules from a directory of YAML files (original behaviour, used by tests).
    /// files loaded from directories can't enforce, only alert
    pub fn new_from_dir<P: AsRef<Path>>(rules_dir: P) -> Self {
        let engine = Self::new_engine();
        let mut rules = Vec::new();

        if let Ok(entries) = fs::read_dir(rules_dir) {
            for entry in entries.flatten() {
                if let Ok(contents) = fs::read_to_string(entry.path())
                    && let Ok(rule) = serde_yaml::from_str::<Rule>(&contents)
                {
                    Self::try_add_rule(&engine, &mut rules, rule, true);
                }
            }
        }
        Self { engine, rules }
    }

    /// Load rules from a multi-document YAML string (documents separated by
    /// `\n---\n`).  This is the format produced by the build script when
    /// embedding rules into the binary.
    pub fn new_from_yaml_str(yaml: &str) -> Self {
        let engine = Self::new_engine();
        let mut rules = Vec::new();

        for doc in yaml.split("\n---\n") {
            let doc = doc.trim();
            if doc.is_empty() {
                continue;
            }
            match serde_yaml::from_str::<Rule>(doc) {
                Ok(rule) => {
                    Self::try_add_rule(&engine, &mut rules, rule, false);
                }
                Err(err) => {
                    eprintln!("Failed to parse embedded RHAI rule: {err}");
                }
            }
        }
        Self { engine, rules }
    }

    /// Build a combined engine from embedded YAML, an optional on-disk rules
    /// directory, and an optional list of rule names to disable.
    ///
    /// Disabled rules are removed after all sources have been loaded, so a
    /// name from any source can be suppressed.
    ///
    /// files loaded from directories can't enforce, only alert
    pub fn new_combined(
        embedded_yaml: &str,
        extra_rules_dir: Option<&Path>,
        disabled_rules: &[String],
    ) -> Self {
        let engine = Self::new_engine();

        let mut rules = Vec::new();

        // 1. Embedded rules
        for doc in embedded_yaml.split("\n---\n") {
            let doc = doc.trim();
            if doc.is_empty() {
                continue;
            }
            if let Ok(rule) = serde_yaml::from_str::<Rule>(doc) {
                Self::try_add_rule(&engine, &mut rules, rule, false);
            }
        }

        // 2. Extra rules from disk (can override / add to embedded set)
        if let Some(dir) = extra_rules_dir
            && let Ok(entries) = fs::read_dir(dir)
        {
            for entry in entries.flatten() {
                if let Ok(contents) = fs::read_to_string(entry.path())
                    && let Ok(rule) = serde_yaml::from_str::<Rule>(&contents)
                {
                    Self::try_add_rule(&engine, &mut rules, rule, true);
                }
            }
        }

        // 3. Remove disabled rules
        if !disabled_rules.is_empty() {
            rules.retain(|r| !disabled_rules.contains(&r.name));
        }

        Self { engine, rules }
    }

    /// Return the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn eval(&self, event: &ProcessEvent) -> Vec<RuleMatch> {
        let mut scope = event.to_scope();
        // note, any rhai rule can mutate scope. write them in a way that that doesn't happen
        self.rules
            .iter()
            .filter(|rule| {
                self.engine
                    .eval_ast_with_scope::<bool>(&mut scope, &rule.ast)
                    .unwrap_or(false)
            })
            .map(|rule| RuleMatch {
                name: rule.name.clone(),
                mode: rule.mode,
            })
            .collect()
    }
}
