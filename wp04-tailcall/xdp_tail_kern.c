/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define bpfprint(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

struct bpf_map_def SEC("maps")
xdp_progs_map = {
        .type        = BPF_MAP_TYPE_PROG_ARRAY,
        .key_size    = sizeof(unsigned int),
        .value_size  = sizeof(unsigned int),
        .max_entries = 1,
};

SEC("xdp")
int  xdp_main(struct xdp_md *ctx)
{
    bpf_tail_call(ctx, &xdp_progs_map, 0);
    bpfprint("you lose it!\n");
    return XDP_PASS;
}

SEC("xdp_2")
int  xdp_drop(struct xdp_md *ctx)
{
    bpfprint("you got it!\n");
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
