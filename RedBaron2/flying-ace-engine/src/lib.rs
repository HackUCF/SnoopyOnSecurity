// src/lib.rs — full file
use regex::Regex;
use rhai::{AST, Dynamic, Engine, Scope};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::{fmt, fs, path::Path};

// -----------------------------------------------------------------------------
// ECS‑compatible event struct (minimal subset – extend as needed)
// -----------------------------------------------------------------------------
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProcessEvent {
    pub timestamp: String,
    pub ecs_version: String,

    // event.*
    pub event_kind: String,
    pub event_category: String,
    pub event_type: String,
    pub event_action: Option<String>,
    pub event_code: Option<String>,
    pub event_module: Option<String>,

    // process.*
    pub process_name: String,
    pub process_pid: u32,
    pub process_args: Option<String>,
    pub process_executable: Option<String>,
    pub process_ppid: Option<u32>,
    pub process_pname: Option<String>, // parent name
    pub process_working_directory: Option<String>,

    // host.*
    pub host_name: Option<String>,
    pub host_id: Option<String>,

    // user.*
    pub user_name: Option<String>,
    pub user_id: Option<u32>,

    // agent.*
    pub agent_type: Option<String>,
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
    // event.*
    fn get_event_kind(&mut self) -> Dynamic {
        self.event_kind.clone().into()
    }
    fn get_event_category(&mut self) -> Dynamic {
        self.event_category.clone().into()
    }
    fn get_event_type(&mut self) -> Dynamic {
        self.event_type.clone().into()
    }
    fn get_event_action(&mut self) -> Dynamic {
        self.event_action
            .clone()
            .map(Into::into)
            .unwrap_or(Dynamic::UNIT)
    }
    fn get_event_code(&mut self) -> Dynamic {
        self.event_code
            .clone()
            .map(Into::into)
            .unwrap_or(Dynamic::UNIT)
    }
    fn get_event_module(&mut self) -> Dynamic {
        self.event_module
            .clone()
            .map(Into::into)
            .unwrap_or(Dynamic::UNIT)
    }
    // process.*
    fn get_process_name(&mut self) -> Dynamic {
        self.process_name.clone().into()
    }
    fn get_process_pid(&mut self) -> Dynamic {
        (self.process_pid as i64).into()
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
    fn get_process_ppid(&mut self) -> Dynamic {
        self.process_ppid
            .map(|v| (v as i64).into())
            .unwrap_or(Dynamic::UNIT)
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
    fn get_user_id(&mut self) -> Dynamic {
        self.user_id
            .map(|v| (v as i64).into())
            .unwrap_or(Dynamic::UNIT)
    }

    // agent.*
    fn get_agent_type(&mut self) -> Dynamic {
        self.agent_type
            .clone()
            .map(Into::into)
            .unwrap_or(Dynamic::UNIT)
    }
}

// -----------------------------------------------------------------------------
// YAML rule representation
// -----------------------------------------------------------------------------
#[derive(Debug, Deserialize)]
pub struct Rule {
    pub name: String,
    pub eval: String,
}

#[derive(Debug)]
struct CompiledRule {
    name: String,
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
    pub fn new_from_dir<P: AsRef<Path>>(rules_dir: P) -> Self {
        let mut engine = Engine::new();

        // add in custom functions to rhai language
        // XXX: may want to implement cache for pre-compiled regex rules
        engine.register_fn("re_match", |text: Dynamic, pattern: &str| -> bool {
            // Turn () or any Dynamic into &str
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
            .register_get("ecs_version", ProcessEvent::get_ecs_version)
            // event.*
            .register_get("event_kind", ProcessEvent::get_event_kind)
            .register_get("event_category", ProcessEvent::get_event_category)
            .register_get("event_type", ProcessEvent::get_event_type)
            .register_get("event_action", ProcessEvent::get_event_action)
            .register_get("event_code", ProcessEvent::get_event_code)
            .register_get("event_module", ProcessEvent::get_event_module)
            // process.*
            .register_get("process_name", ProcessEvent::get_process_name)
            .register_get("process_pid", ProcessEvent::get_process_pid)
            .register_get("process_args", ProcessEvent::get_process_args)
            .register_get("process_executable", ProcessEvent::get_process_executable)
            .register_get("process_ppid", ProcessEvent::get_process_ppid)
            .register_get("process_pname", ProcessEvent::get_process_pname)
            .register_get(
                "process_working_directory",
                ProcessEvent::get_process_working_directory,
            )
            // host.*
            .register_get("host_name", ProcessEvent::get_host_name)
            .register_get("host_id", ProcessEvent::get_host_id)
            // user.*
            .register_get("user_name", ProcessEvent::get_user_name)
            .register_get("user_id", ProcessEvent::get_user_id)
            // agent.*
            .register_get("agent_type", ProcessEvent::get_agent_type);

        let mut rules = Vec::new();

        if let Ok(entries) = fs::read_dir(rules_dir) {
            for entry in entries.flatten() {
                if let Ok(contents) = fs::read_to_string(entry.path())
                    && let Ok(rule) = serde_yaml::from_str::<Rule>(&contents)
                {
                    match engine.compile(&rule.eval) {
                        Ok(ast) => {
                            rules.push(CompiledRule {
                                name: rule.name,
                                ast,
                            });
                        }
                        Err(err) => {
                            eprintln!("Failed to compile rule '{}': {err}", rule.name);
                        }
                    }
                }
            }
        }
        Self { engine, rules }
    }

    pub fn eval(&self, event: &ProcessEvent) -> Vec<String> {
        let scope = event.to_scope();
        self.rules
            .iter()
            .filter(|rule| {
                self.engine
                    .eval_ast_with_scope::<bool>(&mut scope.clone(), &rule.ast)
                    .unwrap_or(false)
            })
            .map(|rule| rule.name.clone())
            .collect()
    }
}
