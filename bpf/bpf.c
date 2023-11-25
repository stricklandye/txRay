// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define RECEIVE 0
#define SEND 1

#define swap(a,b) { __typeof__(a) temp; temp = a; a = b; b = temp; }
#define IPv4 4
#define IPv6 6
#define TCP 6
#define UDP 17

// https://elixir.bootlin.com/linux/v5.15.80/source/include/uapi/linux/if.h#L33
#define IFNAMSIZ 16

struct tcp_key_t {
    __u32 saddr;
    __u32 daddr;
    __u16 lport;
    __u16 dport;
    u8 protocol;
};
struct tcp_key_t *unused_tcp_key __attribute__((unused));

struct tcp_val_t {
    u64 sent;
    u64 recv;
    u32 pid;
    u8 dev_name[IFNAMSIZ];
    u8 comm[16];
};
struct tcp_val_t *unused_tcp_val __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct tcp_key_t);
	__type(value, struct tcp_val_t);
} traffic_map SEC(".maps");


static inline int trace(struct sk_buff *skb,int mode) {
    u16	network_header = BPF_CORE_READ(skb,network_header);
    u16 transport_header = BPF_CORE_READ(skb,transport_header);
    struct net_device *dev = BPF_CORE_READ(skb,dev);
    unsigned char *head = BPF_CORE_READ(skb,head);
    u8 ip_version;

    bpf_probe_read_kernel(&ip_version,sizeof(u8),(void*)head+network_header);
    ip_version = ip_version >> 4 & 0xf;
    if (ip_version == IPv4) {
        struct iphdr ipv4_header;
        struct tcphdr tcp_header;
        struct tcp_key_t tcp_key = {};

        bpf_probe_read_kernel(&ipv4_header,sizeof(struct iphdr),(void*)head + network_header);
        if (ipv4_header.protocol != TCP && ipv4_header.protocol != UDP ) {
            return 0;
        }
        bpf_probe_read_kernel(&tcp_header,sizeof(struct tcphdr),(void*)head + transport_header);
        tcp_key.saddr = bpf_ntohl(ipv4_header.saddr);
        tcp_key.daddr = bpf_ntohl(ipv4_header.daddr);
        tcp_key.lport = bpf_ntohs(tcp_header.source);
        tcp_key.dport = bpf_ntohs(tcp_header.dest);
        tcp_key.protocol = ipv4_header.protocol;
        u16 tot_len = bpf_ntohs(ipv4_header.tot_len);
        if (mode == SEND) {
            struct tcp_val_t *prev_val = bpf_map_lookup_elem(&traffic_map,&tcp_key);
            if (prev_val == NULL) {
                struct tcp_val_t sent_val = {};

                bpf_probe_read_kernel_str(&sent_val.dev_name,IFNAMSIZ,dev->name);
                sent_val.pid = bpf_get_current_pid_tgid() >> 32;
                sent_val.sent = tot_len;
                bpf_get_current_comm(&sent_val.comm,sizeof(sent_val.comm));
                bpf_map_update_elem(&traffic_map,&tcp_key,&sent_val,BPF_NOEXIST);
            } else {
                prev_val->sent += tot_len;
                bpf_map_update_elem(&traffic_map,&tcp_key,prev_val,BPF_EXIST);
            }
        } else if (mode == RECEIVE) {
            swap(tcp_key.saddr,tcp_key.daddr);
            swap(tcp_key.lport,tcp_key.dport);
            struct tcp_val_t *prev_val = bpf_map_lookup_elem(&traffic_map,&tcp_key);
            if (prev_val == NULL) {
                struct tcp_val_t recv_val = {};

                bpf_probe_read_kernel_str(&recv_val.dev_name,IFNAMSIZ,dev->name);
                recv_val.pid = bpf_get_current_pid_tgid() >> 32;
                recv_val.sent = tot_len;
                bpf_get_current_comm(&recv_val.comm,sizeof(recv_val.comm));
                bpf_map_update_elem(&traffic_map,&tcp_key,&recv_val,BPF_NOEXIST);
            } else {
                prev_val->recv += tot_len;
                bpf_map_update_elem(&traffic_map,&tcp_key,prev_val,BPF_EXIST);
            }
        }
    } 
    return 0;
}

struct recv_skb_ctx {
    unsigned long pad;
    struct sk_buff *skb;
    unsigned int len;
    char name[4];
};

SEC("tp/netif_receive_skb")
int tp_netif_receive_skb(struct recv_skb_ctx *ctx) {
    struct sk_buff *skb = ctx->skb;
    trace(skb,RECEIVE);
    return 0;
}

struct net_dev_queue_ctx{
    unsigned long pad;
    struct sk_buff *skb;
    unsigned int len;
    char name[4];
};

SEC("tp/net_dev_queue")
int tp_net_dev_queue(struct net_dev_queue_ctx *ctx) {
    struct sk_buff *skb = ctx->skb;
    trace(skb,SEND);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";