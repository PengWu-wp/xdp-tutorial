#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "bpf.h"

static const char *file_path = "/sys/fs/bpf/blacklist";

unsigned int Dotdec2u32(char *ipaddr) {
    printf("Dotdec2u32 is %u\n", inet_addr(ipaddr));
    return inet_addr(ipaddr);
}

char *u32_2_dotdec(unsigned int ipaddr) {
    char *ip_dotdec;
    struct in_addr ia = {ipaddr};
    ip_dotdec = inet_ntoa(ia);
    return ip_dotdec;
}

int main(int number, char *parameter[]) {
    int fd, value = 0, result;
    unsigned int key;
    fd = bpf_obj_get(file_path);
    if (fd < 0) {
        printf("Failed to fetch the map: %d (%s)\n", fd, strerror(errno));
        return -1;
    } else printf("map fetched, fd is %d\n", fd);

    if (number < 2 || number > 3) {
        printf("Wrong input! Usage: ./map <add/del> <ipaddr>\n");
    } else {
        if (!strcmp(parameter[1], "add")) {
            key = Dotdec2u32(parameter[2]);
            result = bpf_map_update_elem(fd, &key, &value, BPF_ANY);   //更新映射元素
            if (result == 0) {
                printf("Map updated with %s\n", parameter[1]);
            } else {
                printf("Failed to update map: %d (%s)\n", result, strerror(errno));
            }
        } else if (!strcmp(parameter[1], "del")) {
            if (!strcmp(parameter[2], "all")) {
                unsigned int next_key, lookup_key;
                lookup_key = -1;
                char *ipdot_addr;
                while (bpf_map_get_next_key(fd, &lookup_key, &next_key) == 0) {
                    result = bpf_map_delete_elem(fd, &next_key);   //删除映射元素
                    if (result != 0) {
                        printf("Failed to delete map: %d (%s)\n", result, strerror(errno));
                    }
                    lookup_key = next_key;
                }
                printf("map cleared\n");
            } else {
                key = Dotdec2u32(parameter[2]);
                result = bpf_map_delete_elem(fd, &key);   //删除映射元素
                if (result == 0) {
                    printf("%s deleted in blacklist\n", parameter[1]);
                } else {
                    printf("Failed to delete map: %d (%s)\n", result, strerror(errno));
                }
            }
        } else if (!strcmp(parameter[1], "show") && !strcmp(parameter[2], "all")) {
            unsigned int next_key, lookup_key;
            lookup_key = -1;
            printf("black_list_ipaddr:\n");
            char *ipdot_addr;
            while (bpf_map_get_next_key(fd, &lookup_key, &next_key) == 0) {
                ipdot_addr = u32_2_dotdec(next_key);
                printf("%s\n", ipdot_addr);
                lookup_key = next_key;
            }
        } else {
            printf("Wrong input! Usage: ./map <add/del> <ipaddr>\n");
        }
    }

    return 0;
}
