// https://github.com/elastic/ebpf/blob/main/GPL/Events/Process/Probe.bpf.c
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// combined EbpfEventProto.h, Varlen.h, and Helpers.h

const volatile int consumer_pid = 0; // needs to be set in userspace
const volatile int IOV_OFFSET = 0;   // iov_iter->iov which was renamed to __iov

/*
 * kernel v6.15-rc1 changed struct tty_driver.
 * from
 * short type;
 * short subtype;
 * to
 * enum tty_driver_type type;
 * enum tty_driver_subtype subtype;
 * this makes regular CORE macros hard to load
 */
const volatile int DRIVER_TYPE_OFFSET = 0;    // tty_driver.type
const volatile int DRIVER_SUBTYPE_OFFSET = 0; // tty_driver.subtype

#define TASK_COMM_LEN 16

// 256 KiB per cpu core, of which 128 KiB is useable as we have to bound each
// new variable-length field to start at no more than half the size of the
// buffer to make the verifier happy.
//
// 128 KiB is currently more than large enough to handle the largest
// theoretical event, but should be bumped in the future if that changes or
// else the verifier will start to complain.
//
// I have cut all the above values in half from what elastic does
#define EVENT_BUFFER_SIZE (1 << 17)
#define EVENT_BUFFER_SIZE_HALF (EVENT_BUFFER_SIZE >> 1)
#define EVENT_BUFFER_SIZE_HALF_MASK (EVENT_BUFFER_SIZE_HALF - 1)
#define EVENT_SIZE(x)                                                          \
  ((sizeof(*x) + x->vl_fields.size) & (EVENT_BUFFER_SIZE - 1))

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 21); // 2 MiB (cut in half from elastic's 4 MiB)
} ringbuf SEC(".maps");

struct ebpf_pid_info {
  uint64_t start_time_ns;
  uint32_t tid;
  // uint32_t tgid;
  uint32_t ppid;
  // uint32_t pgid;
  uint32_t sid;
} __attribute__((packed));

struct ebpf_event_header {
  uint64_t ts;
  uint64_t ts_boot;
  uint64_t type;
} __attribute__((packed));

struct ebpf_tty_winsize {
  uint16_t rows;
  uint16_t cols;
} __attribute__((packed));

struct ebpf_tty_dev {
  uint16_t minor;
  uint16_t major;
  struct ebpf_tty_winsize winsize;
} __attribute__((packed));

struct ebpf_varlen_fields_start {
  uint32_t nfields;
  size_t size;
  char data[];
} __attribute__((packed));

struct ebpf_process_tty_write_event {
  struct ebpf_event_header hdr;
  struct ebpf_pid_info pids;
  uint64_t tty_out_truncated;

  // Controlling TTY.
  struct ebpf_tty_dev ctty;

  // Destination TTY.
  struct ebpf_tty_dev tty;
  char comm[TASK_COMM_LEN];

  // Variable length fields: tty_out
  struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

enum ebpf_varlen_field_type {
  EBPF_VL_FIELD_CWD,
  EBPF_VL_FIELD_ARGV,
  EBPF_VL_FIELD_ENV,
  EBPF_VL_FIELD_FILENAME,
  EBPF_VL_FIELD_PATH,
  EBPF_VL_FIELD_OLD_PATH,
  EBPF_VL_FIELD_NEW_PATH,
  EBPF_VL_FIELD_TTY_OUT,
  EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH,
  EBPF_VL_FIELD_SYMLINK_TARGET_PATH,
  EBPF_VL_FIELD_MOD_VERSION,
  EBPF_VL_FIELD_MOD_SRCVERSION,
};

struct ebpf_varlen_field {
  enum ebpf_varlen_field_type type;
  uint32_t size;
  char data[];
} __attribute__((packed));

enum ebpf_event_type {
  EBPF_EVENT_PROCESS_INVALID = 0,
  EBPF_EVENT_PROCESS_FORK = (1 << 0),
  EBPF_EVENT_PROCESS_EXEC = (1 << 1),
  EBPF_EVENT_PROCESS_EXIT = (1 << 2),
  EBPF_EVENT_PROCESS_SETSID = (1 << 3),
  EBPF_EVENT_PROCESS_SETUID = (1 << 4),
  EBPF_EVENT_PROCESS_SETGID = (1 << 5),
  EBPF_EVENT_PROCESS_TTY_WRITE = (1 << 6),
  EBPF_EVENT_FILE_DELETE = (1 << 7),
  EBPF_EVENT_FILE_CREATE = (1 << 8),
  EBPF_EVENT_FILE_RENAME = (1 << 9),
  EBPF_EVENT_FILE_MODIFY = (1 << 10),
  EBPF_EVENT_FILE_MEMFD_OPEN = (1 << 11),
  EBPF_EVENT_FILE_SHMEM_OPEN = (1 << 12),
  EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED = (1 << 13),
  EBPF_EVENT_NETWORK_CONNECTION_ATTEMPTED = (1 << 14),
  EBPF_EVENT_NETWORK_CONNECTION_CLOSED = (1 << 15),
  EBPF_EVENT_PROCESS_MEMFD_CREATE = (1 << 16),
  EBPF_EVENT_PROCESS_SHMGET = (1 << 17),
  EBPF_EVENT_PROCESS_PTRACE = (1 << 18),
  EBPF_EVENT_PROCESS_LOAD_MODULE = (1 << 19),
};

#define TTY_OUT_MAX 8192
#define TASK_COMM_LEN 16

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, EVENT_BUFFER_SIZE);
  __uint(max_entries, 0); // Will be resized by userspace to $(nproc)
} event_buffer_map SEC(".maps");

static void *get_event_buffer() {
  int key = bpf_get_smp_processor_id();
  return bpf_map_lookup_elem(&event_buffer_map, &key);
}

static void ebpf_pid_info__fill(struct ebpf_pid_info *pi,
                                const struct task_struct *task) {
  /*
  int e_pgid;

  if (bpf_core_enum_value_exists(enum pid_type, PIDTYPE_PGID))
    e_pgid = bpf_core_enum_value(enum pid_type, PIDTYPE_PGID);
  else
    e_pgid = PIDTYPE_PGID;

  pi->tgid = BPF_CORE_READ(task, tgid);
  pi->pgid =
      BPF_CORE_READ(task, group_leader, signal, pids[e_pgid], numbers[0].nr);
  */
  pi->tid = BPF_CORE_READ(task, pid);
  pi->ppid = BPF_CORE_READ(task, group_leader, real_parent, tgid);
  pi->start_time_ns = BPF_CORE_READ(task, group_leader, start_time);

  int e_sid;
  if (bpf_core_enum_value_exists(enum pid_type, PIDTYPE_SID))
    e_sid = bpf_core_enum_value(enum pid_type, PIDTYPE_SID);
  else
    e_sid = PIDTYPE_SID;

  struct pid *spid = BPF_CORE_READ(task, group_leader, signal, pids[e_sid]);
  if (!spid)
    return;
  u32 nr = 0;
  const struct upid *u =
      ((const char *)spid + bpf_core_field_offset(struct pid, numbers));
  bpf_core_read(&nr, sizeof(nr), &u->nr);
  pi->sid = nr;
  /* aya hates this, idk why so the hacky solution above is used
  pi->sid =
      BPF_CORE_READ(task, group_leader, signal, pids[e_sid], numbers[0].nr);
  */
}

static void ebpf_tty_dev__fill(struct ebpf_tty_dev *tty_dev,
                               const struct tty_struct *tty) {
  tty_dev->major = BPF_CORE_READ(tty, driver, major);
  tty_dev->minor = BPF_CORE_READ(tty, driver, minor_start);
  tty_dev->minor += BPF_CORE_READ(tty, index);

  struct winsize winsize = BPF_CORE_READ(tty, winsize);
  struct ebpf_tty_winsize ws = {};
  ws.rows = winsize.ws_row;
  ws.cols = winsize.ws_col;
  tty_dev->winsize = ws;
}

static void ebpf_ctty__fill(struct ebpf_tty_dev *ctty,
                            const struct task_struct *task) {
  struct tty_struct *tty = BPF_CORE_READ(task, signal, tty);
  ebpf_tty_dev__fill(ctty, tty);
}

void ebpf_vl_fields__init(struct ebpf_varlen_fields_start *fields) {
  fields->nfields = 0;
  fields->size = 0;
}

struct ebpf_varlen_field *
ebpf_vl_field__add(struct ebpf_varlen_fields_start *fields,
                   enum ebpf_varlen_field_type type) {
  struct ebpf_varlen_field *new_field =
      (struct ebpf_varlen_field
           *)(&fields->data[fields->size & EVENT_BUFFER_SIZE_HALF_MASK]);
  new_field->type = type;
  fields->nfields++;
  return new_field;
}

void ebpf_vl_field__set_size(struct ebpf_varlen_fields_start *vl_fields,
                             struct ebpf_varlen_field *field, size_t size) {
  vl_fields->size += size + sizeof(struct ebpf_varlen_field);
  field->size = size;
}

struct ebpf_event_stats {
  uint64_t lost; // lost events due to a full ringbuffer
  uint64_t sent; // events sent through the ringbuffer
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct ebpf_event_stats);
  __uint(max_entries, 1);
} ringbuf_stats SEC(".maps");

static long ebpf_ringbuf_write(void *ringbuf, void *data, u64 size, u64 flags) {
  long r;
  struct ebpf_event_stats *ees;
  u32 zero = 0;

  r = bpf_ringbuf_output(ringbuf, data, size, flags);
  ees = bpf_map_lookup_elem(&ringbuf_stats, &zero);
  if (ees != NULL)
    r == 0 ? ees->sent++ : ees->lost++;

  return (r);
}

static bool is_consumer() {
  int pid = bpf_get_current_pid_tgid() >> 32;
  return consumer_pid == pid;
}

#define MAX_NR_SEGS 8
#define ECHO 0x00008
#define TTY_DRIVER_TYPE_PTY 0x0004
#define PTY_TYPE_MASTER 0x0001

static u64 bpf_ktime_get_boot_ns_helper() {
  if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_ktime_get_boot_ns))
    return bpf_ktime_get_boot_ns();
  else
    return 0;
}

static __always_inline bool tty_echo_enabled(const struct tty_struct *tty) {
  struct ktermios t = BPF_CORE_READ(tty, termios);
  return (t.c_lflag & ECHO) != 0;
}

// Probe.bpf.c

// will not output events of base_len 0
static int output_tty_event(struct ebpf_tty_dev *slave, const void *base,
                            size_t base_len) {
  struct ebpf_process_tty_write_event *event;
  struct ebpf_varlen_field *field;
  const struct task_struct *task;
  int ret = 0;

  // new code not in Elastic
  if (base_len == 0)
    goto out; // leave ret = 0

  event = get_event_buffer();
  if (!event) {
    ret = 1;
    goto out;
  }

  task = (struct task_struct *)bpf_get_current_task();
  ebpf_pid_info__fill(&event->pids, task);
  event->hdr.type = EBPF_EVENT_PROCESS_TTY_WRITE;
  event->hdr.ts = bpf_ktime_get_ns();
  event->hdr.ts_boot = bpf_ktime_get_boot_ns_helper();
  u64 len_cap = base_len > TTY_OUT_MAX ? TTY_OUT_MAX : base_len;
  event->tty_out_truncated =
      base_len > TTY_OUT_MAX ? base_len - TTY_OUT_MAX : 0;
  event->tty = *slave;
  ebpf_ctty__fill(&event->ctty, task);
  bpf_get_current_comm(event->comm, TASK_COMM_LEN);

  // Variable length fields
  ebpf_vl_fields__init(&event->vl_fields);

  // tty_out
  field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_TTY_OUT);
  if (bpf_probe_read_user(field->data, len_cap, base)) {
    ret = 1;
    goto out;
  }

  ebpf_vl_field__set_size(&event->vl_fields, field, len_cap);
  ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0);
out:
  return ret;
}

static int tty_write__enter(struct kiocb *iocb, struct iov_iter *from) {
  if (is_consumer()) {
    goto out;
  }

  struct file *f = BPF_CORE_READ(iocb, ki_filp);
  struct tty_file_private *tfp =
      (struct tty_file_private *)BPF_CORE_READ(f, private_data);
  struct tty_struct *tty = BPF_CORE_READ(tfp, tty);

  // Obtain the real TTY
  //
  // @link: link to another pty (master -> slave and vice versa)
  //
  // https://elixir.bootlin.com/linux/v5.19.9/source/drivers/tty/tty_io.c#L2643
  bool is_master = false;
  struct ebpf_tty_dev master = {};
  struct ebpf_tty_dev slave = {};

  struct tty_driver *driver = BPF_CORE_READ(tty, driver);

  u16 type = 0;
  u16 subtype = 0;

  // see note near volatile const definition
  bpf_probe_read_kernel(
      &type, sizeof(type),
      (const void *)((const char *)driver + DRIVER_TYPE_OFFSET));
  bpf_probe_read_kernel(
      &subtype, sizeof(subtype),
      (const void *)((const char *)driver + DRIVER_SUBTYPE_OFFSET));

  bool master_echo = true;
  bool slave_echo = true;
  if (type == TTY_DRIVER_TYPE_PTY && subtype == PTY_TYPE_MASTER) {
    struct tty_struct *tmp = BPF_CORE_READ(tty, link);
    ebpf_tty_dev__fill(&master, tty);
    ebpf_tty_dev__fill(&slave, tmp);
    master_echo = tty_echo_enabled(tty);
    slave_echo = tty_echo_enabled(tmp);
    is_master = true;
  } else {
    ebpf_tty_dev__fill(&slave, tty);
    slave_echo = tty_echo_enabled(tty);
  }

  if (slave.major == 0 && slave.minor == 0) {
    goto out;
  }

  if ((is_master && !master_echo) && !slave_echo) {
    goto out;
  }

  const struct iovec *iov;

  if (bpf_core_field_exists(from->__iov)) {
    iov = BPF_CORE_READ(from, __iov);
  } else if (IOV_OFFSET != 0) {
    long err = bpf_probe_read_kernel(
        &iov, sizeof(iov), (const void *)((const char *)from + IOV_OFFSET));
    if (err)
      goto out;
  } else {
    goto out;
  }

  // modified from elastic's repo, they used nr_segs as an of ubuf
  // doesn't seem reliable on newer kernels
  if (bpf_core_field_exists(from->iter_type) &&
      bpf_core_enum_value_exists(enum iter_type, ITER_UBUF)) {
    u8 iter_type = BPF_CORE_READ(from, iter_type);
    u8 iter_ubuf = bpf_core_enum_value(enum iter_type, ITER_UBUF);

    if (iter_type == iter_ubuf) {
      u64 count = BPF_CORE_READ(from, count);
      (void)output_tty_event(&slave, (void *)iov, count);
      goto out;
    }
  }

  u64 nr_segs = BPF_CORE_READ(from, nr_segs);
  nr_segs = nr_segs > MAX_NR_SEGS ? MAX_NR_SEGS : nr_segs;

  for (int seg = 0; seg < nr_segs; seg++) {
    // NOTE(matt): this check needs to be here because the verifier
    // detects an infinite loop otherwise.
    if (seg >= MAX_NR_SEGS)
      goto out;

    struct iovec *cur_iov = (struct iovec *)&iov[seg];
    const char *base = BPF_CORE_READ(cur_iov, iov_base);
    size_t len = BPF_CORE_READ(cur_iov, iov_len);

    if (output_tty_event(&slave, base, len)) {
      goto out;
    }
  }

out:
  return 0;
}

// tty_write became this kiocb, iov_iter api in kernel version v5.10.11

SEC("fentry/tty_write")
int BPF_PROG(fentry__tty_write, struct kiocb *iocb, struct iov_iter *from) {
  return tty_write__enter(iocb, from);
}

SEC("kprobe/tty_write")
int BPF_KPROBE(kprobe__tty_write, struct kiocb *iocb, struct iov_iter *from) {
  return tty_write__enter(iocb, from);
}
