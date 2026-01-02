#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_ARG_CHARS 32
#define MAX_ARGS 8

#define MAX_PATH_COMPONENT_SIZE 32
#define MAX_PATH_COMPONENTS 8
#define TASK_COMM_LEN 16

struct execve_args {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

struct args {
    __u32 argc;
    char args[MAX_ARGS][MAX_ARG_CHARS];
};

struct process_event {
    __u64 timestamp; // ns since system boot

    __u32 pid;
    __u32 ppid;
    __u32 uid;

    char name[TASK_COMM_LEN]; // comm
    char pname[TASK_COMM_LEN]; // parent comm

    struct args argv;
    char executable[MAX_PATH_COMPONENTS][MAX_PATH_COMPONENT_SIZE]; // split path
    char working_directory[MAX_PATH_COMPONENTS][MAX_PATH_COMPONENT_SIZE]; // split cwd
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

// per-CPU scratch space for building events
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_event);
} scratch_event SEC(".maps");

static __always_inline void extract_argv(struct execve_args *ctx, struct args *out) {
    out->argc = 0;
#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        if (bpf_probe_read(&argp, sizeof(argp), &ctx->argv[i]) < 0)
            break;
        if (!argp)
            break;
        bpf_probe_read(out->args[i], MAX_ARG_CHARS, argp);
        out->args[i][MAX_ARG_CHARS - 1] = 0; // force NUL
        out->argc++;
    }
}

/* Walk dentry chain (basename-first order). */
static __always_inline void extract_dentry_path(struct dentry *dentry,
                                                char out[MAX_PATH_COMPONENTS][MAX_PATH_COMPONENT_SIZE]) {
    __builtin_memset(out, 0, MAX_PATH_COMPONENTS * MAX_PATH_COMPONENT_SIZE);

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        if (!dentry)
            break;

        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        if (dentry == parent)
            break;

        const struct qstr d_name = BPF_CORE_READ(dentry, d_name);
        bpf_probe_read(out[i], MAX_PATH_COMPONENT_SIZE, d_name.name);
        out[i][MAX_PATH_COMPONENT_SIZE - 1] = 0;

        dentry = parent;
    }
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec_enter(struct execve_args *ctx) {
    __u32 key = 0;
    struct process_event *e = bpf_map_lookup_elem(&scratch_event, &key);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    
    e->timestamp = bpf_ktime_get_ns();
    
    extract_argv(ctx, &e->argv);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exec_exit(struct trace_event_raw_sys_exit *ctx) {
    __u32 key = 0;
    struct process_event *e = bpf_map_lookup_elem(&scratch_event, &key);
    if (!e)
        return 0;

    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    e->pid = BPF_CORE_READ(task, pid);
    e->ppid = BPF_CORE_READ(task, real_parent, pid);
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    bpf_core_read(e->pname, sizeof(e->pname), &parent->comm);
    bpf_get_current_comm(&e->name, sizeof(e->name));

    // full executable path via exe_file->f_path.dentry
    struct dentry *exe_dentry = BPF_CORE_READ(task, mm, exe_file, f_path.dentry);
    if (exe_dentry)
        extract_dentry_path(exe_dentry, e->executable);
    
    // cwd task->fs->pwd.dentry
    struct dentry *cwd_dentry = BPF_CORE_READ(task, fs, pwd.dentry);
    if (cwd_dentry)
        extract_dentry_path(cwd_dentry, e->working_directory);

    // user info
    e->uid = BPF_CORE_READ(task, real_cred, uid.val);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));

    return 0;
}
