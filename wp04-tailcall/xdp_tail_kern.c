/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps")
xdp_progs_map = {
        .type        = BPF_MAP_TYPE_PROG_ARRAY,
        .key_size    = sizeof(unsigned int),
        .value_size  = sizeof(unsigned int),
        .max_entries = 100,
};

SEC("xdp")
int  xdp_main(struct xdp_md *ctx)
{
    bpf_tail_call(ctx, &xdp_progs_map, 1);
    return XDP_DROP;
}

SEC("xdp")
int  xdp_pass(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";