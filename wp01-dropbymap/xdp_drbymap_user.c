
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/types.h>

static const char *file_path = "/sys/fs/bpf/black_list";

int main(int number, char *parameter[]) {
    int prog_fd = -1;
    int err;
    int ifindex = -1;
    char filename[256] = "xdp_drbymap_kern.o";
    bool detach = false;
    struct bpf_object *obj;
    __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST ;//| XDP_FLAGS_SKB_MODE;
    //首先简单处理参数：
    if (number < 2 || number > 3) {
        printf("inputwrong! Usage: ./runme <dev_name> <load/detach>\n");
    } else {
        ifindex = if_nametoindex(parameter[1]);
        if (!ifindex) {
            printf("interface %s does not exist!\n", parameter[1]);
            exit(-1);
        }
        if (!strcmp(parameter[2], "load")) {
            detach = false;
        } else if (!strcmp(parameter[2], "detach")) {
            detach = true;
        } else {
            printf("inputwrong! Usage: ./runme <dev_name> <load/detach>\n");
            exit(-2);
        }
    }
    //根据指定的标志，进行XDP程序的加载或卸载
    if (detach) {
        int err;///引用bpf_set_link_xdp_fd将中间参数置-1以detach XDP程序
        if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
            fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
                    err, strerror(-err));
            return -3;
        } else {
            printf("XDP prog detached from %s\n", parameter[1]);
        }
    } else {
        // bpf_prog_load用以加载XDP程序，会将prog_fd更改为XDP程序的fd
        err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
        if (err) {
            fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
                    filename, err, strerror(-err));
            return -1;
        } else {
            printf("prog load success!\n");
        }
        // 还是用这个函数进行attachv
        err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
        if (err < 0) {
            fprintf(stderr, "ERR: "
                            "ifindex(%d) link set xdp fd failed (%d): %s\n",
                    ifindex, -err, strerror(-err));
        } else {
            printf("prog attached success to %s\n", parameter[1]);
            
        }
        int fd =-1;
        fd= bpf_object__find_map_fd_by_name(obj,"blacklist_map");
        if(fd < 0)printf("fd not found!\n");
        else printf("map fd is %d\n",fd);
        int pinned = bpf_obj_pin(fd, file_path);    //命令映射保存到虚拟文件系统中
        if (pinned < 0) {
            printf("Failed to pin map to the file system: %d (%s)\n", pinned,
                strerror(errno));
        return -1;
        } else printf("map pinned to %s\n",file_path);
  /*
  unsigned int key = 2200479936;
  int value = 1024;
  int result = bpf_map_update_elem(fd, &key, &value, BPF_ANY);   //读取映射元素
  if (result == 0) {
    printf("Map updated!\n");
  }else{
      printf("Failed to update map: %d (%s)\n", result, strerror(errno));
  }*/
        
    }
    return 0;
}
