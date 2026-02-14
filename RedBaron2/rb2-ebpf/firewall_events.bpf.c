#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define AF_INET6 10

enum op_kind {
  OP_CONNECT = 1,
  OP_SENDTO = 2,
  OP_SENDMSG = 3,
  OP_SENDMMSG = 4,
  OP_ACCEPT = 5,
  OP_BIND = 6,
};

struct event {
  int pid;
  __u32 op;
  __u16 family;
  __u16 dport;
  __u8 comm[16];
  union {
    __u32 v4;
    __u8 v6[16];
  } addr;
};

struct dedupe_key {
  __u32 tgid;
  __u32 op;
  __u16 family;
  __u16 dport;
  union {
    __u32 v4;
    __u8 v6[16];
  } dst;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 128);
  __type(key, struct dedupe_key);
  __type(value, __u64);
} seen SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct accept_args {
  void *uaddr;
  void *uaddrlen;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 512);
  __type(key, __u32);
  __type(value, struct accept_args);
} accept_inflight SEC(".maps");

// local filters

static __always_inline bool is_ipv4_nonpublic(__u32 addr_be) {
  __u32 addr = __builtin_bswap32(addr_be);

  if ((addr & 0xFF000000u) == 0x00000000u)
    return true; // 0.0.0.0/8
  if ((addr & 0xFF000000u) == 0x7F000000u)
    return true; // 127/8

  if ((addr & 0xFF000000u) == 0x0A000000u)
    return true; // 10/8
  if ((addr & 0xFFF00000u) == 0xAC100000u)
    return true; // 172.16/12
  if ((addr & 0xFFFF0000u) == 0xC0A80000u)
    return true; // 192.168/16

  if ((addr & 0xFFFF0000u) == 0xA9FE0000u)
    return true; // 169.254/16
  if ((addr & 0xFFC00000u) == 0x64400000u)
    return true; // 100.64/10

  if ((addr & 0xF0000000u) == 0xE0000000u)
    return true; // 224/4 multicast
  if (addr == 0xFFFFFFFFu)
    return true; // broadcast

  return false;
}

// don't let bind return true for 0.0.0.0/8
static __always_inline bool is_ipv4_nonpublic_bind(__u32 addr_be) {
  __u32 addr = __builtin_bswap32(addr_be);

  if ((addr & 0xFF000000u) == 0x7F000000u)
    return true; // 127/8

  if ((addr & 0xFF000000u) == 0x0A000000u)
    return true; // 10/8
  if ((addr & 0xFFF00000u) == 0xAC100000u)
    return true; // 172.16/12
  if ((addr & 0xFFFF0000u) == 0xC0A80000u)
    return true; // 192.168/16

  if ((addr & 0xFFFF0000u) == 0xA9FE0000u)
    return true; // 169.254/16
  if ((addr & 0xFFC00000u) == 0x64400000u)
    return true; // 100.64/10

  if ((addr & 0xF0000000u) == 0xE0000000u)
    return true; // 224/4 multicast
  if (addr == 0xFFFFFFFFu)
    return true; // broadcast

  return false;
}

static __always_inline bool ipv6_all_zero(const struct in6_addr *addr) {
  __u8 b[16] = {};
  if (BPF_CORE_READ_INTO(&b, addr, in6_u.u6_addr8))
    return false;
#pragma unroll
  for (int i = 0; i < 16; i++) {
    if (b[i] != 0)
      return false;
  }
  return true;
}

static __always_inline bool is_ipv6_nonpublic(const struct in6_addr *addr) {
  __u8 b[16] = {};
  if (BPF_CORE_READ_INTO(&b, addr, in6_u.u6_addr8))
    return true; // conservative

  // :: (unspecified)
  bool all0 = true;
#pragma unroll
  for (int i = 0; i < 16; i++) {
    if (b[i] != 0) {
      all0 = false;
      break;
    }
  }
  if (all0)
    return true;

  // ::1 loopback
  bool loop = true;
#pragma unroll
  for (int i = 0; i < 15; i++) {
    if (b[i] != 0) {
      loop = false;
      break;
    }
  }
  if (loop && b[15] == 1)
    return true;

  // fe80::/10 link-local
  if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)
    return true;

  // fc00::/7 unique local
  if ((b[0] & 0xFE) == 0xFC)
    return true;

  // ff00::/8 multicast
  if (b[0] == 0xFF)
    return true;

  return false;
}

static __always_inline bool
is_ipv6_nonpublic_bind(const struct in6_addr *addr) {
  __u8 b[16] = {};
  if (BPF_CORE_READ_INTO(&b, addr, in6_u.u6_addr8))
    return true; // conservative

  // ::1 loopback
  bool loop = true;
#pragma unroll
  for (int i = 0; i < 15; i++) {
    if (b[i] != 0) {
      loop = false;
      break;
    }
  }
  if (loop && b[15] == 1)
    return true;

  // fe80::/10 link-local
  if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)
    return true;

  // fc00::/7 unique local
  if ((b[0] & 0xFE) == 0xFC)
    return true;

  // ff00::/8 multicast
  if (b[0] == 0xFF)
    return true;

  return false;
}

#ifndef DEDUPE_TTL_NS
#define DEDUPE_TTL_NS (30ULL * 1000ULL * 1000ULL * 1000ULL) // 30s
#endif

static __always_inline int maybe_emit(void *ctx, const struct dedupe_key *k) {
  __u64 now = bpf_ktime_get_ns();

  __u64 *last = bpf_map_lookup_elem(&seen, k);
  if (last && (now - *last) < DEDUPE_TTL_NS)
    return 0;

  bpf_map_update_elem(&seen, k, &now, BPF_ANY);

  struct event ev = {};
  ev.pid = k->tgid;
  ev.op = k->op;
  ev.family = k->family;
  ev.dport = k->dport;
  bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

  if (k->family == AF_INET) {
    ev.addr.v4 = k->dst.v4;
  } else if (k->family == AF_INET6) {
#pragma unroll
    for (int i = 0; i < 16; i++)
      ev.addr.v6[i] = k->dst.v6[i];
  }

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
  return 0;
}

static __always_inline int emit_from_user_sockaddr(void *ctx, void *uservaddr,
                                                   int addrlen, __u32 op,
                                                   bool for_bind) {
  if (!uservaddr || addrlen <= 0)
    return 0;

  __u16 family = BPF_CORE_READ_USER((struct sockaddr *)uservaddr, sa_family);
  if (!family)
    return 0;

  struct dedupe_key k = {};
  k.tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  k.op = op;

  if (family == AF_INET) {
    if (addrlen < (int)sizeof(struct sockaddr_in))
      return 0;

    struct sockaddr_in sin = {};
    if (bpf_core_read_user(&sin, sizeof(sin), uservaddr))
      return 0;

    if (!for_bind) {
      if (is_ipv4_nonpublic(sin.sin_addr.s_addr))
        return 0;
    } else {
      // ephemeral binds
      if (sin.sin_port == 0)
        return 0;

      if (sin.sin_addr.s_addr != 0 &&
          is_ipv4_nonpublic_bind(sin.sin_addr.s_addr))
        return 0;
    }

    k.family = AF_INET;
    k.dport = __builtin_bswap16(sin.sin_port);
    k.dst.v4 = sin.sin_addr.s_addr;
    return maybe_emit(ctx, &k);
  }

  if (family == AF_INET6) {
    if (addrlen < (int)sizeof(struct sockaddr_in6))
      return 0;

    struct sockaddr_in6 sin6 = {};
    if (bpf_core_read_user(&sin6, sizeof(sin6), uservaddr))
      return 0;

    if (!for_bind) {
      if (is_ipv6_nonpublic(&sin6.sin6_addr))
        return 0;
    } else {
      // ephemeral binds
      if (sin6.sin6_port == 0)
        return 0;

      if (!ipv6_all_zero(&sin6.sin6_addr) &&
          is_ipv6_nonpublic_bind(&sin6.sin6_addr))
        return 0;
    }

    k.family = AF_INET6;
    k.dport = __builtin_bswap16(sin6.sin6_port);

    __u8 b[16] = {};
    if (bpf_core_read_user(b, sizeof(b), &sin6.sin6_addr.in6_u.u6_addr8))
      return 0;

#pragma unroll
    for (int i = 0; i < 16; i++)
      k.dst.v6[i] = b[i];

    return maybe_emit(ctx, &k);
  }

  return 0;
}

// hooks

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
  void *uservaddr = (void *)ctx->args[1];
  int addrlen = (int)ctx->args[2];
  return emit_from_user_sockaddr(ctx, uservaddr, addrlen, OP_CONNECT, false);
}

SEC("tracepoint/syscalls/sys_enter_bind")
int tp_sys_enter_bind(struct trace_event_raw_sys_enter *ctx) {
  void *uservaddr = (void *)ctx->args[1];
  int addrlen = (int)ctx->args[2];
  return emit_from_user_sockaddr(ctx, uservaddr, addrlen, OP_BIND, true);
}

SEC("tracepoint/syscalls/sys_enter_accept")
int tp_sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
  __u32 tid = (__u32)bpf_get_current_pid_tgid();
  struct accept_args a = {
      .uaddr = (void *)ctx->args[1],
      .uaddrlen = (void *)ctx->args[2],
  };
  bpf_map_update_elem(&accept_inflight, &tid, &a, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tp_sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {
  __u32 tid = (__u32)bpf_get_current_pid_tgid();
  struct accept_args *a = bpf_map_lookup_elem(&accept_inflight, &tid);
  if (!a)
    return 0;

  if ((int)ctx->ret >= 0) {
    int addrlen = 0;
    if (a->uaddrlen)
      bpf_probe_read_user(&addrlen, sizeof(addrlen), a->uaddrlen);
    emit_from_user_sockaddr(ctx, a->uaddr, addrlen, OP_ACCEPT, false);
  }

  bpf_map_delete_elem(&accept_inflight, &tid);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int tp_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
  __u32 tid = (__u32)bpf_get_current_pid_tgid();
  struct accept_args a = {
      .uaddr = (void *)ctx->args[1],
      .uaddrlen = (void *)ctx->args[2],
  };
  bpf_map_update_elem(&accept_inflight, &tid, &a, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int tp_sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
  __u32 tid = (__u32)bpf_get_current_pid_tgid();
  struct accept_args *a = bpf_map_lookup_elem(&accept_inflight, &tid);
  if (!a)
    return 0;

  if ((int)ctx->ret >= 0) {
    int addrlen = 0;
    if (a->uaddrlen)
      bpf_probe_read_user(&addrlen, sizeof(addrlen), a->uaddrlen);
    emit_from_user_sockaddr(ctx, a->uaddr, addrlen, OP_ACCEPT, false);
  }

  bpf_map_delete_elem(&accept_inflight, &tid);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tp_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
  // args: fd, buf, len, flags, dest, addrlen
  void *uservaddr = (void *)ctx->args[4];
  int addrlen = (int)ctx->args[5];

  // dest == NULL is an already connected socket; drop to avoid noise
  if (!uservaddr)
    return 0;

  return emit_from_user_sockaddr(ctx, uservaddr, addrlen, OP_SENDTO, false);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tp_sys_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
  // args: fd, user_msghdr *msg, flags
  void *umsg = (void *)ctx->args[1];
  if (!umsg)
    return 0;

  struct user_msghdr mh = {};
  if (bpf_core_read_user(&mh, sizeof(mh), umsg))
    return 0;

  // msg_name == NULL is an already connected socket; drop to avoid noise.
  if (!mh.msg_name || mh.msg_namelen <= 0)
    return 0;

  return emit_from_user_sockaddr(ctx, mh.msg_name, (int)mh.msg_namelen,
                                 OP_SENDMSG, false);
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int tp_sys_enter_sendmmsg(struct trace_event_raw_sys_enter *ctx) {
  // args: fd, mmsghdr *vmessages, vlen, flags
  void *vmessages = (void *)ctx->args[1];
  __u32 vlen = (__u32)ctx->args[2];
  if (!vmessages || vlen == 0)
    return 0;

  struct user_msghdr mh = {};
  if (BPF_CORE_READ_USER_INTO(&mh, (struct mmsghdr *)vmessages, msg_hdr))
    return 0;

  if (!mh.msg_name || mh.msg_namelen <= 0)
    return 0;

  return emit_from_user_sockaddr(ctx, mh.msg_name, (int)mh.msg_namelen,
                                 OP_SENDMMSG, false);
}
