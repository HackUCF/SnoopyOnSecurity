#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAP_SIZE 5000

struct ipv4_key_t {
  u16 sport;
  u32 daddr;
  u16 dport;
} __attribute__((packed));

struct owner {
  u64 pid;
  char comm[TASK_COMM_LEN];
} __attribute__((packed));

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct ipv4_key_t);
  __type(value, struct owner);
  __uint(max_entries, MAP_SIZE);
} tcpMap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct ipv4_key_t);
  __type(value, struct owner);
  __uint(max_entries, MAP_SIZE);
} udpMap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, u64);
  __uint(max_entries, 300);
} tcpsock SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, u64);
  __uint(max_entries, 300);
} icmpsock SEC(".maps");

//
// TCP v4 connection tracking
//
SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  u64 skp = (u64)sk;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&tcpsock, &pid_tgid, &skp, BPF_ANY);
  return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 *skp = bpf_map_lookup_elem(&tcpsock, &pid_tgid);
  if (!skp)
    return 0;

  struct sock *sk = (struct sock *)*skp;
  struct ipv4_key_t tcp_key = {};

  tcp_key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
  tcp_key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
  tcp_key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

  tcp_key.daddr = __builtin_bswap32(tcp_key.daddr);
  tcp_key.dport = __builtin_bswap16(tcp_key.dport);

  struct owner tcp_value = {};
  tcp_value.pid = pid_tgid >> 32;
  bpf_get_current_comm(&tcp_value.comm, sizeof(tcp_value.comm));
  bpf_map_update_elem(&tcpMap, &tcp_key, &tcp_value, BPF_ANY);

  bpf_map_delete_elem(&tcpsock, &pid_tgid);
  return 0;
}

//
// UDP v4 tracking
//
SEC("kprobe/udp_sendmsg")
int kprobe__udp_sendmsg(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

  struct sockaddr_in *usin = BPF_CORE_READ(msg, msg_name);
  struct ipv4_key_t udp_key = {};

  if (usin) {
    udp_key.dport = BPF_CORE_READ(usin, sin_port);
    udp_key.daddr = BPF_CORE_READ(usin, sin_addr.s_addr);
  }

  if (udp_key.dport == 0) {
    udp_key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    udp_key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  }

  udp_key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);

  udp_key.dport = __builtin_bswap16(udp_key.dport);
  udp_key.daddr = __builtin_bswap32(udp_key.daddr);

  struct owner *lookedupValue = bpf_map_lookup_elem(&udpMap, &udp_key);
  u64 pid = bpf_get_current_pid_tgid() >> 32;
  if (!lookedupValue || lookedupValue->pid != pid) {
    struct owner udp_value = {};
    udp_value.pid = pid;
    bpf_get_current_comm(&udp_value.comm, sizeof(udp_value.comm));
    bpf_map_update_elem(&udpMap, &udp_key, &udp_value, BPF_ANY);
  }
  return 0;
}

//
// ICMP/DGRAM connection tracking
//
SEC("kprobe/inet_dgram_connect")
int kprobe__inet_dgram_connect(struct pt_regs *ctx) {
  struct socket *skt = (struct socket *)PT_REGS_PARM1(ctx);
  struct sockaddr *saddr = (struct sockaddr *)PT_REGS_PARM2(ctx);

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 skp = (u64)skt;
  u64 sa = (u64)saddr;
  bpf_map_update_elem(&tcpsock, &pid_tgid, &skp, BPF_ANY);
  bpf_map_update_elem(&icmpsock, &pid_tgid, &sa, BPF_ANY);
  return 0;
}

SEC("kretprobe/inet_dgram_connect")
int kretprobe__inet_dgram_connect(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 *skp = bpf_map_lookup_elem(&tcpsock, &pid_tgid);
  u64 *sap = bpf_map_lookup_elem(&icmpsock, &pid_tgid);
  if (!skp || !sap)
    goto out;

  struct socket *skt = (struct socket *)*skp;
  struct sock *sk = BPF_CORE_READ(skt, sk);

  u8 proto = BPF_CORE_READ(sk, sk_protocol);

  struct owner udp_value = {};
  udp_value.pid = pid_tgid >> 32;
  bpf_get_current_comm(&udp_value.comm, sizeof(udp_value.comm));

  struct sockaddr_in *ska = (struct sockaddr_in *)*sap;
  struct ipv4_key_t udp_key = {};
  udp_key.daddr = BPF_CORE_READ(ska, sin_addr.s_addr);
  udp_key.dport = BPF_CORE_READ(ska, sin_port);

  if (udp_key.dport == 0) {
    udp_key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    udp_key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  }

  udp_key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);

  udp_key.dport = __builtin_bswap16(udp_key.dport);
  udp_key.daddr = __builtin_bswap32(udp_key.daddr);
  udp_key.sport = (udp_key.sport >> 8) | ((udp_key.sport << 8) & 0xff00);

  if (udp_key.dport == 0 || udp_key.daddr == 0)
    goto out;

  if (proto == IPPROTO_UDP) {
    bpf_map_update_elem(&udpMap, &udp_key, &udp_value, BPF_ANY);
  } else {
    bpf_printk("Unknown proto found %d (pid=%llu)\n", proto, udp_value.pid);
  }

  return 0;
out:
  bpf_map_delete_elem(&tcpsock, &pid_tgid);
  bpf_map_delete_elem(&icmpsock, &pid_tgid);
  return 0;
}

//
// Tunnel tracking
//
SEC("kprobe/iptunnel_xmit")
int kprobe__iptunnel_xmit(struct pt_regs *ctx) {
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
  u32 dst = (u32)PT_REGS_PARM5(ctx);

  struct ipv4_key_t udp_key = {};
  struct owner udp_value = {};

  u16 pkt_hdr = BPF_CORE_READ(skb, transport_header);
  unsigned char *head = BPF_CORE_READ(skb, head);
  struct udphdr *udph = (struct udphdr *)(head + pkt_hdr);

  u16 sport = BPF_CORE_READ(udph, source);
  udp_key.dport = BPF_CORE_READ(udph, dest);

  udp_key.dport = __builtin_bswap16(udp_key.dport);
  sport = (sport >> 8) | ((sport << 8) & 0xff00);

  udp_key.sport = sport;
  udp_key.daddr = __builtin_bswap32(dst);

  struct owner *lookedupValue = bpf_map_lookup_elem(&udpMap, &udp_key);
  u64 pid = bpf_get_current_pid_tgid() >> 32;
  if (!lookedupValue || lookedupValue->pid != pid) {
    udp_value.pid = pid;
    bpf_get_current_comm(&udp_value.comm, sizeof(udp_value.comm));
    bpf_map_update_elem(&udpMap, &udp_key, &udp_value, BPF_ANY);
  }
  return 0;
}
