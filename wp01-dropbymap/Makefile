

XDP_TARGETS := xdp_drbymap_kern
USER_TARGETS := xdp_drbymap_user

LLC ?= llc
CLANG ?= clang
CC := gcc

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/
LOADINCLUDE += -I../libbpf/include/uapi
LOADINCLUDE += -I../libbpf/src/build/usr/include
LOADINCLUDE += -I../libbpf/src/build/usr/include/bpf

include $(COMMON_DIR)/common.mk
COMMON_OBJS := $(COMMON_DIR)/common_params.o

.PHONY: clean

clean:
	rm -f *.o map *.ll map_manage xdp_drbymap_user

map: map
	clang -o map_manage $(LOADINCLUDE) -lbpf map_manage.c

