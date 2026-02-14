//! Integration-tests for the Rhai rule engine
//! (lives in `tests/engine.rs`, so it is compiled as a
//! separate crate that depends on `flying_ace_engine`)
#[cfg(test)]
mod tests {
    use flying_ace_engine::{EcsRhaiEngine, ProcessEvent, RuleMode};
    use serde::Deserialize;

    /// Convenience helper – the engine always loads rules from `rules/`
    fn new_engine() -> EcsRhaiEngine {
        EcsRhaiEngine::new_from_dir("rules")
    }

    /// An empty `ProcessEvent` with sensible defaults.
    fn base_event() -> ProcessEvent {
        ProcessEvent {
            timestamp: "2025-06-04T12:00:00Z".into(),
            ecs_version: "8.11.0".into(),
            event_category: "process".into(),
            event_module: None,
            process_name: String::new(),
            process_pid: 0,
            process_sid: 0,
            process_args: None,
            process_executable: None,
            process_ppid: None,
            process_pname: None,
            process_working_directory: None,
            host_name: None,
            host_id: None,
            user_name: None,
            user_id: None,
        }
    }

    // =========================================================================
    // Deserialization structs for YAML rule files (including embedded tests)
    // =========================================================================

    #[derive(Debug, Deserialize)]
    struct TestCase {
        cleartext: String,
        #[serde(default)]
        process_name: Option<String>,
        #[serde(default)]
        process_args: Option<String>,
        #[serde(default)]
        process_executable: Option<String>,
        #[serde(default)]
        process_pname: Option<String>,
        #[serde(default)]
        process_working_directory: Option<String>,
        #[serde(default)]
        user_name: Option<String>,
        #[serde(default)]
        user_id: Option<u32>,
        #[serde(default)]
        event_category: Option<String>,
        should_match: bool,
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct RuleWithTests {
        name: String,
        #[serde(default = "default_mode")]
        mode: String,
        eval: String,
        #[serde(default)]
        tests: Vec<TestCase>,
    }

    fn default_mode() -> String {
        "alert".to_string()
    }

    /// Build a ProcessEvent from a TestCase, filling defaults from base_event()
    fn event_from_test_case(tc: &TestCase) -> ProcessEvent {
        let mut ev = base_event();
        if let Some(ref name) = tc.process_name {
            ev.process_name = name.clone();
        }
        if let Some(ref args) = tc.process_args {
            ev.process_args = Some(args.clone());
        }
        if let Some(ref exe) = tc.process_executable {
            ev.process_executable = Some(exe.clone());
        }
        if let Some(ref pname) = tc.process_pname {
            ev.process_pname = Some(pname.clone());
        }
        if let Some(ref cwd) = tc.process_working_directory {
            ev.process_working_directory = Some(cwd.clone());
        }
        if let Some(ref uname) = tc.user_name {
            ev.user_name = Some(uname.clone());
        }
        if tc.user_id.is_some() {
            ev.user_id = tc.user_id;
        }
        if let Some(ref cat) = tc.event_category {
            ev.event_category = cat.clone();
        }
        ev
    }

    /// Run all embedded tests for a single YAML rule file.
    fn run_rule_yaml(yaml_file: &str) {
        let path = std::path::Path::new("rules").join(yaml_file);
        let contents =
            std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("cannot read {:?}", path));
        let rule: RuleWithTests = serde_yaml::from_str(&contents)
            .unwrap_or_else(|e| panic!("{}: failed to deserialize: {}", path.display(), e));

        assert!(
            !rule.tests.is_empty(),
            "rule '{}' in {} has no embedded tests",
            rule.name,
            path.display()
        );

        let engine = EcsRhaiEngine::new_from_dir(path.parent().unwrap());

        for (i, tc) in rule.tests.iter().enumerate() {
            let event = event_from_test_case(tc);
            let matches = engine.eval(&event);
            let did_match = matches.iter().any(|m| m.name == rule.name);

            assert_eq!(
                did_match, tc.should_match,
                "\nrule='{}' test[{}] cleartext='{}'\n  process_name='{}' process_args={:?}\n",
                rule.name, i, tc.cleartext, event.process_name, event.process_args,
            );
        }
    }

    // =========================================================================
    // One #[test] per rule YAML — each shows up individually in `cargo test`
    // =========================================================================

    macro_rules! rule_test {
        ($test_name:ident, $yaml_file:expr) => {
            #[test]
            fn $test_name() {
                run_rule_yaml($yaml_file);
            }
        };
    }

    // --- new detection rules ---
    rule_test!(rule_bash_c_execution, "bash_c.yaml");
    rule_test!(rule_ansible_usage, "ansible.yaml");
    rule_test!(rule_wall_usage, "wall.yaml");
    rule_test!(rule_curl_wget_download, "curl_wget_download.yaml");
    rule_test!(rule_curl_pipe_bash, "curl_pipe_bash.yaml");
    rule_test!(rule_webserver_shell_spawn, "webserver_shell.yaml");
    rule_test!(rule_ncat_reverse_shell, "ncat_revshell.yaml");
    rule_test!(rule_python_reverse_shell, "python_revshell.yaml");
    rule_test!(rule_root_ssh_login, "root_ssh_login.yaml");
    rule_test!(rule_bash_base64_execute, "bash_base64_exec.yaml");
    rule_test!(rule_process_from_memory, "process_from_mem.yaml");
    rule_test!(rule_compilation_detected, "compilation.yaml");
    rule_test!(rule_dd_usage, "dd_usage.yaml");
    rule_test!(rule_rm_rf_no_preserve_root, "rm_rf_nopreserve.yaml");
    rule_test!(rule_linux_hack_tool, "linux_hack_tool.yaml");

    // --- original unit test rules ---
    rule_test!(rule_suspicious_process, "unit_test_1.yaml");
    rule_test!(rule_reverse_shell_nc, "unit_test_2.yaml");
    rule_test!(rule_curl_upload_file, "unit_test_3.yaml");
    rule_test!(rule_exec_from_tmp, "unit_test_4.yaml");
    rule_test!(rule_bash_base64_execution, "unit_test_5.yaml");
    rule_test!(rule_curl_upload_file_regex, "unit_test_6.yaml");
    rule_test!(rule_privileged_user_uid0, "unit_test_7.yaml");

    // =========================================================================
    // Verify mode parsing works correctly
    // =========================================================================

    #[test]
    fn rule_mode_defaults_to_alert() {
        let engine = new_engine();
        let mut event = base_event();
        event.process_name = "bash".into();
        event.process_args = Some("bash -c whoami".into());

        let matches = engine.eval(&event);
        for m in &matches {
            if m.name == "bash_c_execution" {
                assert_eq!(
                    m.mode,
                    RuleMode::Alert,
                    "Expected bash_c_execution to default to Alert mode"
                );
            }
        }
    }
}
