#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>


#define SEC(NAME) __attribute__((section(NAME), used))


#define bpfprint(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

struct bpf_map_def SEC("maps") blacklist_map = {
        .type        = BPF_MAP_TYPE_HASH,
        .key_size    = sizeof(unsigned int),
        .value_size  = sizeof(unsigned int),
        .max_entries = 100,
};

SEC("xdp")
int xdp_dropbyproto(struct xdp_md *ctx) {
    int ipsize = 0;
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    ipsize = sizeof(*eth);
    ip = data + ipsize;
    ipsize += sizeof(struct iphdr);
    if (data + ipsize > data_end) { // 防止verifier报错
        return XDP_DROP;
    }

    bpfprint("src:%u,dest:%u\n", ip->saddr, ip->daddr);

    unsigned int key = ip->saddr;

    unsigned int *value;
    value = bpf_map_lookup_elem(&blacklist_map, &key);
    //bpfprint("result %u\n", value);
    if (value) {
        bpfprint("ip found in blacklist, dropped\n");
        return XDP_DROP;
    } else {
        bpfprint("Good to pass\n");
        return XDP_PASS;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";