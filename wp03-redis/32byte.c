/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#ifndef be16
#define be16 __be16
#endif
#ifndef be32
#define be32 __be32
#endif
#ifndef u32
#define u32 __u32
#endif
#ifndef u16
#define u16 __u16
#endif
#ifndef htonl
#define htonl __constant_htonl
#endif
#ifndef ntohl
#define ntohl __constant_ntohl
#endif
#ifndef htons
#define htons __constant_htons
#endif
#ifndef ntohs
#define ntohs __constant_ntohs
#endif


#define bpfprint(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

struct tcp_header_option { // seems like this is fixed struct?
    be32 options;
    be32 tsv;
    be32 tsv_r;
} __attribute__((__packed__));


struct bpf_map_def SEC("maps")
blacklist_map = {
        .type        = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(unsigned int),
        .value_size  = sizeof(unsigned int),
        .max_entries = 100,
};

static inline __u16 compute_ip_checksum(struct iphdr *ip) {
    u32 csum = 0;
    u16 *next_ip_u16 = (u16 *) ip;


    ip->check = 0;

#pragma clang loop unroll(full)
    for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
        csum += *next_ip_u16++;
    }

    return ~((csum & 0xffff) + (csum >> 16));
}

static inline __u16
compute_tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, struct tcp_header_option *tcphdr_ops, char *payload, int offset) {
    u32 csum = 0;
    int i;
    int payload_size;
    u16 *next_tcp_u16 = (u16 *) &ip->saddr;

#pragma clang loop unroll(full)
    for (i = 0; i < 4 + (sizeof(*tcp) >> 1) + (sizeof(*tcphdr_ops) >> 1); i++) {
        csum += ntohs(*next_tcp_u16);
        next_tcp_u16 = next_tcp_u16 + 1;
    }
    csum += ntohs(0x0600); // TCP protocol 0x06
    csum += (offset + 32);
    if (offset % 2 != 0) {
        payload[offset] = 0x00;
        payload_size = (offset + 1) >> 1;
    } else {
        payload_size = offset >> 1;
    }
    next_tcp_u16 = (u16 *) payload;

#pragma clang loop unroll(full)
    for (i = 0; i < payload_size; i++) {
        csum += ntohs(*next_tcp_u16);
        next_tcp_u16 = next_tcp_u16 + 1;
    }

    return htons(~((csum & 0xffff) + (csum >> 16)));
}

SEC("xdp")
int bmc_rx_filter_main(struct xdp_md *ctx) {
    void *data_end = (void *) (long) ctx->data_end;
    void *data = (void *) (long) ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    void *transp = data + sizeof(*eth) + sizeof(*ip);
    struct tcphdr *tcp;
    struct tcp_header_option *tcphdr_ops;
    char *payload;
    int payload_len = 39;   /// change payload len here!
    be16 ip_totlen_old;
    be16 dport;

    unsigned char tmp_mac[ETH_ALEN];
    be32 tmp_ip;
    be16 tmp_port;
    be32 tmp_seqnum;

    be32 tmp_tsv;

    unsigned int key = 0;
    unsigned int *value;
    value = bpf_map_lookup_elem(&blacklist_map, &key);

    if (ip + 1 > data_end)
        return XDP_PASS;

    switch (ip->protocol) {
        case IPPROTO_TCP:
            tcp = (struct tcphdr *) transp;
            if (tcp + 1 > data_end)
                return XDP_PASS;
            dport = tcp->dest;
            if(dport != htons(6379))
                return XDP_PASS;
            tcphdr_ops = transp + sizeof(*tcp);
            payload = transp + sizeof(*tcp) + sizeof(*tcphdr_ops);
            break;
        default:
            return XDP_PASS;
    }
    if (payload + 39 <= data_end) {
        if ((payload[8] == 'g' || payload[8] == 'G') && (payload[9] == 'e' || payload[9] == 'E') &&
            (payload[10] == 't' || payload[10] == 'T')) { // This is a GET request

            memcpy(tmp_mac, eth->h_source, ETH_ALEN);
            memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
            memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

            tmp_ip = ip->saddr;
            ip->saddr = ip->daddr;
            ip->daddr = tmp_ip;

            tmp_port = tcp->source;
            tcp->source = tcp->dest;
            tcp->dest = tmp_port;
            ip_totlen_old = ntohs(ip->tot_len);
            ip->tot_len = htons(52 + payload_len);

            ip->id = htons(16218); // no need to change
            ip->check = compute_ip_checksum(ip);

            tmp_seqnum = tcp->seq;
            tcp->seq = tcp->ack_seq; // auto
            tcp->ack_seq = ntohl(htonl(tmp_seqnum) + ip_totlen_old - 52); // auto

            tcp->window = 0xfd01; // fixed for now...

            tmp_tsv = tcphdr_ops->tsv;
            tcphdr_ops->tsv = ntohl(htonl(tcphdr_ops->tsv_r) + 200); // Must change, or client will not return the right ACK num.
            tcphdr_ops->tsv_r = tmp_tsv;

            payload[0] = '$';
            payload[1] = '3';   /// if you change data, change here!
            payload[2] = '2';
            payload[3] = 0x0d;
            payload[4] = 0x0a;
            payload[5] = 'e';
            payload[6] = 'l';
            payload[7] = 'l';
            payload[8] = 'o';   /// if you change data, change here!
            payload[9] = 'h';
            payload[10] = 'e';
            payload[11] = 'l';
            payload[12] = 'l';
            payload[13] = 'o';   /// if you change data, change here!
            payload[14] = 'h';
            payload[15] = 'e';
            payload[16] = 'l';
            payload[17] = 'l';
            payload[18] = 'o';   /// if you change data, change here!
            payload[19] = 'h';
            payload[20] = 'e';
            payload[21] = 'l';
            payload[22] = 'l';
            payload[23] = 'o';   /// if you change data, change here!
            payload[24] = 'h';
            payload[25] = 'e';
            payload[26] = 'l';
            payload[27] = 'l';
            payload[28] = 'o';   /// if you change data, change here!
            payload[29] = 'h';
            payload[30] = 'e';
            payload[31] = 'l';
            payload[32] = 'l';
            payload[33] = 'o';   /// if you change data, change here!
            payload[34] = 'h';
            payload[35] = 'e';
            payload[36] = 'e';
            payload[37] = 0x0d;
            payload[38] = 0x0a; // static for now...
            tcp->check = 0;
            if(payload + payload_len + 1 <= data_end){
                tcp->check = compute_tcp_checksum(ip, tcp, tcphdr_ops, payload, payload_len);
            }
            bpf_xdp_adjust_tail(ctx, -(ip_totlen_old - 52 - payload_len));
            return XDP_TX;
        } else {
            return XDP_PASS;
        }
    }
    return XDP_PASS;
}

char _license[]
SEC("license") = "GPL";
