//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET         2
#define AF_INET6        10
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

#define MAX_CONN_ENTRIES  10240
#define MAX_PROC_ENTRIES  4096
#define MAX_SOCK_PID_ENTRIES 10240

// 5-tuple + pid identifies a unique traffic flow per process.
// saddr/daddr are 16 bytes to hold both IPv4 (first 4 bytes, rest zero)
// and IPv6 (full 16 bytes) addresses.
struct conn_key {
    __u32 pid;
    __u8  saddr[16];
    __u8  daddr[16];
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  family;
    __u8  pad[2];
};

struct conn_stats {
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 rx_packets;
    __u64 last_ns;
    __u32 rtt_us;  // smoothed RTT in microseconds; 0 until first measurement
    __u32 _pad;
    char  comm[16];
};

struct proc_stats {
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 rx_packets;
    __u64 last_ns;
    __u64 retrans_pkts;
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN_ENTRIES);
    __type(key, struct conn_key);
    __type(value, struct conn_stats);
} conn_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PROC_ENTRIES);
    __type(key, __u32);
    __type(value, struct proc_stats);
} proc_stats_map SEC(".maps");

// Maps a socket pointer to its owning PID, populated in user-context kprobes.
// Allows tcp_retransmit_skb (which runs in softirq/timer context) to find the PID.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SOCK_PID_ENTRIES);
    __type(key, __u64);
    __type(value, __u32);
} sock_pid_map SEC(".maps");

static __always_inline void
record_traffic(struct sock *sk, __u64 bytes, bool is_tx, __u8 proto) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (pid == 0)
        return;

    // Register socket → PID so tcp_retransmit_skb can find the owner.
    __u64 sk_ptr = (__u64)(uintptr_t)sk;
    bpf_map_update_elem(&sock_pid_map, &sk_ptr, &pid, BPF_ANY);

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return;

    struct conn_key key = {};
    key.pid    = pid;
    key.proto  = proto;
    key.family = (__u8)family;
    key.sport  = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport  = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (family == AF_INET) {
        __u32 s4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 d4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(key.saddr, &s4, 4);
        __builtin_memcpy(key.daddr, &d4, 4);
    } else {
        struct in6_addr s6, d6;
        BPF_CORE_READ_INTO(&s6, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&d6, sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(key.saddr, s6.in6_u.u6_addr8, 16);
        __builtin_memcpy(key.daddr, d6.in6_u.u6_addr8, 16);
    }

    // Update per-connection stats
    struct conn_stats *cs = bpf_map_lookup_elem(&conn_stats_map, &key);
    if (!cs) {
        struct conn_stats zero = {};
        bpf_get_current_comm(zero.comm, sizeof(zero.comm));
        bpf_map_update_elem(&conn_stats_map, &key, &zero, BPF_NOEXIST);
        cs = bpf_map_lookup_elem(&conn_stats_map, &key);
        if (!cs)
            return;
    }

    if (is_tx) {
        __sync_fetch_and_add(&cs->tx_bytes, bytes);
        __sync_fetch_and_add(&cs->tx_packets, 1);
    } else {
        __sync_fetch_and_add(&cs->rx_bytes, bytes);
        __sync_fetch_and_add(&cs->rx_packets, 1);
    }
    cs->last_ns = bpf_ktime_get_ns();
    // Read smoothed RTT from tcp_sock.srtt_us (stored << 3; divide by 8 for actual μs).
    if (proto == IPPROTO_TCP) {
        struct tcp_sock *tp = (struct tcp_sock *)sk;
        __u32 srtt = BPF_CORE_READ(tp, srtt_us);
        if (srtt > 0)
            cs->rtt_us = srtt >> 3;
    }

    // Update per-process aggregate stats
    struct proc_stats *ps = bpf_map_lookup_elem(&proc_stats_map, &pid);
    if (!ps) {
        struct proc_stats zero = {};
        bpf_get_current_comm(zero.comm, sizeof(zero.comm));
        bpf_map_update_elem(&proc_stats_map, &pid, &zero, BPF_NOEXIST);
        ps = bpf_map_lookup_elem(&proc_stats_map, &pid);
        if (!ps)
            return;
    }

    if (is_tx) {
        __sync_fetch_and_add(&ps->tx_bytes, bytes);
        __sync_fetch_and_add(&ps->tx_packets, 1);
    } else {
        __sync_fetch_and_add(&ps->rx_bytes, bytes);
        __sync_fetch_and_add(&ps->rx_packets, 1);
    }
    ps->last_ns = bpf_ktime_get_ns();
    if (ps->comm[0] == 0)
        bpf_get_current_comm(ps->comm, sizeof(ps->comm));
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    record_traffic(sk, size, true, IPPROTO_TCP);
    return 0;
}

// tcp_cleanup_rbuf is called when userspace reads data from the TCP receive buffer.
// This handles both IPv4 and IPv6 TCP sockets.
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(kprobe_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    if (copied <= 0)
        return 0;
    record_traffic(sk, (__u64)copied, false, IPPROTO_TCP);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    record_traffic(sk, len, true, IPPROTO_UDP);
    return 0;
}

// udpv6_sendmsg handles IPv6 UDP transmit
SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(kprobe_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    record_traffic(sk, len, true, IPPROTO_UDP);
    return 0;
}

// skb_consume_udp is called when UDP data is consumed by userspace (IPv4 and IPv6)
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(kprobe_skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len) {
    if (len <= 0)
        return 0;
    record_traffic(sk, (__u64)len, false, IPPROTO_UDP);
    return 0;
}

// tcp_retransmit_skb fires in softirq context, so bpf_get_current_pid_tgid()
// returns the interrupted kernel thread, not the socket owner. We look up the
// PID from sock_pid_map which was populated when the socket first sent/received.
SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(kprobe_tcp_retransmit_skb, struct sock *sk, struct sk_buff *skb) {
    __u64 sk_ptr = (__u64)(uintptr_t)sk;
    __u32 *pidp = bpf_map_lookup_elem(&sock_pid_map, &sk_ptr);
    if (!pidp)
        return 0;
    __u32 pid = *pidp;

    struct proc_stats *ps = bpf_map_lookup_elem(&proc_stats_map, &pid);
    if (!ps)
        return 0;

    __sync_fetch_and_add(&ps->retrans_pkts, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
