//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET         2
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

#define MAX_CONN_ENTRIES  10240
#define MAX_PROC_ENTRIES  4096

// 5-tuple + pid identifies a unique traffic flow per process
struct conn_key {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
};

struct conn_stats {
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 rx_packets;
    __u64 last_ns;
    char  comm[16];
};

struct proc_stats {
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 rx_packets;
    __u64 last_ns;
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

static __always_inline void
record_traffic(struct sock *sk, __u64 bytes, bool is_tx, __u8 proto) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (pid == 0)
        return;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return;

    __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // Update per-connection stats
    struct conn_key key = {
        .pid   = pid,
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
        .proto = proto,
    };

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

// tcp_cleanup_rbuf is called when userspace reads data from the TCP receive buffer
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

// skb_consume_udp is called when UDP data is consumed by userspace
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(kprobe_skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len) {
    if (len <= 0)
        return 0;
    record_traffic(sk, (__u64)len, false, IPPROTO_UDP);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
