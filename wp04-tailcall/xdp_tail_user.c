/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
                             " - Specify BPF-object --filename to load \n"
                             " - and select BPF section --progsec name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

///////////////////////////////////////////////////////////////////
struct bpf_progs_desc {
    char name[256];
    enum bpf_prog_type type;
    unsigned char pin;
    int map_prog_idx;
    struct bpf_program *prog;
};

static struct bpf_progs_desc progs[] = {
        {"xdp", BPF_PROG_TYPE_XDP, 0, -1, NULL},
        {"xdp_2", BPF_PROG_TYPE_XDP, 0, 0, NULL},
};
///////////////////////////////////////////////////////////////////

static const char *default_filename = "xdp_tail_kern.o";
static const char *default_progsec = "xdp";

static const struct option_wrapper long_options[] = {
        {{"help",        no_argument,		NULL, 'h' },
                            "Show help", false},

        {{"dev",         required_argument,	NULL, 'd' },
                            "Operate on device <ifname>", "<ifname>", true},

        {{"skb-mode",    no_argument,		NULL, 'S' },
                            "Install XDP program in SKB (AKA generic) mode"},

        {{"native-mode", no_argument,		NULL, 'N' },
                            "Install XDP program in native mode"},

        {{"auto-mode",   no_argument,		NULL, 'A' },
                            "Auto-detect SKB or native mode"},

        {{"offload-mode",no_argument,		NULL, 3 },
                            "Hardware offload XDP program to NIC"},

        {{"force",       no_argument,		NULL, 'F' },
                            "Force install, replacing existing program on interface"},

        {{"unload",      no_argument,		NULL, 'U' },
                            "Unload XDP program instead of loading"},

        {{"quiet",       no_argument,		NULL, 'q' },
                            "Quiet mode (no output)"},

        {{"filename",    required_argument,	NULL,  1  },
                            "Load program from <file>", "<file>"},

        {{"progsec",    required_argument,	NULL,  2  },
                            "Load program in <section> of the ELF file", "<section>"},

        {{0, 0, NULL,  0 }, NULL, false}
};

/* Lesson#1: More advanced load_bpf_object_file and bpf_object */
struct bpf_object *__load_bpf_object_file(const char *filename, int ifindex)
{
    /* In next assignment this will be moved into ../common/ */
    int first_prog_fd = -1;
    struct bpf_object *obj;
    int err;

    /* Lesson#3: This struct allow us to set ifindex, this features is used
     * for hardware offloading XDP programs.
     */
    struct bpf_prog_load_attr prog_load_attr = {
            .prog_type	= BPF_PROG_TYPE_XDP,
            .ifindex	= ifindex,
    };
    prog_load_attr.file = filename;

    /* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
     * loading this into the kernel via bpf-syscall
     */
    err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
    if (err) {
        fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
                filename, err, strerror(-err));
        return NULL;
    }

    /* Notice how a pointer to a libbpf bpf_object is returned */
    return obj;
}

/* Lesson#2: This is a central piece of this lesson:
 * - Notice how BPF-ELF obj can have several programs
 * - Find by sec name via: bpf_object__find_program_by_title()
 */
struct bpf_object *__load_bpf_and_xdp_attach(struct config *cfg)
{
    /* In next assignment this will be moved into ../common/ */
    struct bpf_program *bpf_prog;
    struct bpf_object *bpf_obj;
    int offload_ifindex = 0;
    int prog_fd = -1;
    int err;

    /* If flags indicate hardware offload, supply ifindex */
    if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)
        offload_ifindex = cfg->ifindex;

    /* Load the BPF-ELF object file and get back libbpf bpf_object */
    bpf_obj = __load_bpf_object_file(cfg->filename, offload_ifindex);
    if (!bpf_obj) {
        fprintf(stderr, "ERR: loading file: %s\n", cfg->filename);
        exit(EXIT_FAIL_BPF);
    }
    /* At this point: All XDP/BPF programs from the cfg->filename have been
     * loaded into the kernel, and evaluated by the verifier. Only one of
     * these gets attached to XDP hook, the others will get freed once this
     * process exit.
     */

    /* Find a matching BPF prog section name */
    bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
    if (!bpf_prog) {
        fprintf(stderr, "ERR: finding progsec: %s\n", cfg->progsec);
        exit(EXIT_FAIL_BPF);
    }

    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0) {
        fprintf(stderr, "ERR: bpf_program__fd failed\n");
        exit(EXIT_FAIL_BPF);
    }

    /* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
     * is our select file-descriptor handle. Next step is attaching this FD
     * to a kernel hook point, in this case XDP net_device link-level hook.
     */
    err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
    if (err)
        exit(err);

    return bpf_obj;
}

static void list_avail_progs(struct bpf_object *obj)
{
    struct bpf_program *pos;

    printf("BPF object (%s) listing avail --progsec names\n",
           bpf_object__name(obj));

    bpf_object__for_each_program(pos, obj) {
        if (bpf_program__is_xdp(pos))
            printf(" %s\n", bpf_program__title(pos, false));
    }
}

int main(int argc, char **argv)
{
    struct bpf_object *bpf_obj;

    struct config cfg = {
            .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
            .ifindex   = -1,
            .do_unload = false,
    };
    /* Set default BPF-ELF object file and BPF program name */
    strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
    strncpy(cfg.progsec,  default_progsec,  sizeof(cfg.progsec));
    /* Cmdline options can change these */
    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

    /* Required option */
    if (cfg.ifindex == -1) {
        fprintf(stderr, "ERR: required option --dev missing\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }
    if (cfg.do_unload)
        return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
/*
    bpf_obj = __load_bpf_and_xdp_attach(&cfg);

    if (!bpf_obj)
        return EXIT_FAIL_BPF;

    int xdp_progs_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "xdp_progs_map");
    if (xdp_progs_map_fd < 0) {
        fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
        return 1;
    } else {
        printf("xdp_progs_map_fd found %d\n", xdp_progs_map_fd);
    }

    //int map_prog_idx = 0;
*/


///////////////////////////////////////////////////////////////////////////////// open obj to get bpf_obj
    bpf_obj = bpf_object__open(default_filename);
    if (!bpf_obj) {
        fprintf(stderr, "Error: bpf_object__open failed\n");
        return 1;
    } else {
        printf("WP: %s opened, and bpf_obj get!\n",default_filename);
    }
///////////////////////////////////////////////////////////////////////////////// load struch bpf_program(progs.prog) by bpf_obj and sec name
    int prog_count;
    prog_count = sizeof(progs) / sizeof(progs[0]);

    for (int i = 0; i < prog_count; i++) {
        progs[i].prog = bpf_object__find_program_by_title(bpf_obj, progs[i].name);
        if (!progs[i].prog) {
            fprintf(stderr, "Error: bpf_object__find_program_by_title failed\n");
            return 1;
        } else {
            printf("WP: prog sec %s found and got struct bpf_program!\n",progs[i].name);
        }
        bpf_program__set_type(progs[i].prog, progs[i].type);
    }
///////////////////////////////////////////////////////////////////////////////// load bpf_obj into the kernel
    int err;
    struct bpf_object_load_attr load_attr;

    load_attr.obj = bpf_obj;
    load_attr.log_level = LIBBPF_WARN;

    err = bpf_object__load_xattr(&load_attr);
    if (err) {
        fprintf(stderr, "Error: bpf_object__load_xattr failed\n");
        return 1;
    } else {
        printf("WP: bpf_obj loaded into kernel!\n");
    }
///////////////////////////////////////////////////////////////////////////////// get prog_map's fd by its name and bpf_obj
    int xdp_progs_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "xdp_progs_map");
    if (xdp_progs_map_fd < 0) {
        fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
        return 1;
    } else {
        printf("xdp_progs_map_fd found %d\n", xdp_progs_map_fd);
    }
///////////////////////////////////////////////////////////////////////////////// get each sec's prog fd, and update xdp_progs_map
    for (int i = 0; i < prog_count; i++) {
        int prog_fd = bpf_program__fd(progs[i].prog); // each sec's prog fd

        if (prog_fd < 0) {
            fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", progs[i].name);
            return 1;
        } else {
            printf("%s 's prog fd got: %d\n",progs[i].name, prog_fd);
        }

        if (progs[i].map_prog_idx != -1) {
            unsigned int map_prog_idx = progs[i].map_prog_idx;
            if (map_prog_idx < 0) {
                fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", progs[i].name);
                return 1;
            }

            err = bpf_map_update_elem(xdp_progs_map_fd, &map_prog_idx, &prog_fd, 0);
            if (err) {
                fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
                return 1;
            } else {
                printf("xdp_progs_map updated! name: %s, idx: %d, fd: %d\n",progs[i].name,map_prog_idx,prog_fd);
            }
        }
    }

    //__u32 xdp_flags |= XDP_FLAGS_SKB_MODE;
    int xdp_main_prog_fd = bpf_program__fd(progs[0].prog);
    if (xdp_main_prog_fd < 0) {
        fprintf(stderr, "Error: bpf_program__fd failed\n");
        return 1;
    }
    if (bpf_set_link_xdp_fd(cfg.ifindex, xdp_main_prog_fd, XDP_FLAGS_SKB_MODE) < 0) {
        fprintf(stderr, "Error: bpf_set_link_xdp_fd failed for interface %d\n", cfg.ifindex);
        return 1;
    } else {
        printf("Main BPF program attached to XDP on interface %d\n", cfg.ifindex);
    }

    while(1){
        
    }

    if (verbose)
        list_avail_progs(bpf_obj);

    if (verbose) {
        printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
               cfg.filename, cfg.progsec);
        printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
               cfg.ifname, cfg.ifindex);
    }
    /* Other BPF section programs will get freed on exit */
    return EXIT_OK;
}
