#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def SEC("maps") cnt_map = {
        .type        = BPF_MAP_TYPE_HASH,
        .key_size    = sizeof(unsigned int),
        .value_size  = sizeof(unsigned int),
        .max_entries = 10,
};

SEC("xdp")
int xdp_test(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip;
    ip = data + sizeof(*eth);
    if (ip + 1 > data_end)
        return XDP_PASS;

    unsigned int key = 0;
    unsigned int *cnt;
    unsigned int cntnum = 1;
    cnt = bpf_map_lookup_elem(&cnt_map, &key);
    if (cnt) {
        cntnum = *cnt;
        cntnum++;
        bpf_map_update_elem(&cnt_map, &key, &cntnum, BPF_ANY);
    } else {
        bpf_map_update_elem(&cnt_map, &key, &cntnum, BPF_ANY);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
