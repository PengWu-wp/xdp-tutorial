/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <bpf/bpf_helpers.h>

struct xrc_tcp_header {
    __be32 unknown;
    __be32 tsv;
    __be32 tsv_r;
    char data[];
} __attribute__((__packed__));



#define bpfprint(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })


SEC("xdp")
int bmc_rx_filter_main(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	void *transp = data + sizeof(*eth) + sizeof(*ip);
	//struct udphdr *udp;
	struct tcphdr *tcp;
	char *payload;
	__be16 dport;

	struct xrc_tcp_header *xrc_tcp_hdr;

	unsigned char tmp_mac[ETH_ALEN];
	__be32 tmp_ip;
	__be16 tmp_port;
	__be32 tmp_tsv;
	__be32 tmp_seqnum;

	if (ip + 1 > data_end)
		return XDP_PASS;

	switch (ip->protocol) {
		case IPPROTO_TCP:
			tcp = (struct tcphdr *) transp;
			if (tcp + 1 > data_end)
				return XDP_PASS;
			dport = tcp->dest;
			payload = transp + sizeof(*tcp);
			xrc_tcp_hdr = transp + sizeof(*tcp);
			//bpfprint("Got a TCP pkt. To port: %x\n",dport);
			//bpfprint("window: %x, check: %x\n",tcp->window,tcp->check);
			//bpfprint("eth+ip:%d, sizeof(*tcp): %d\n",sizeof(*eth) + sizeof(*ip),sizeof(*tcp));
			
			break;
		default:
			return XDP_PASS;
	}
	if(payload + 23 <= data_end){
		//bpfprint("payload[0] is %x,payload[1] is %x\n",payload[0],payload[1]);
		//bpfprint("payload[2] is %x,payload[3] is %x\n",payload[2],payload[3]);
		//bpfprint("payload[4] is %x,payload[5] is %x\n",payload[4],payload[5]);
		//bpfprint("payload[6] is %x,payload[7] is %x\n",payload[6],payload[7]);
		//bpfprint("payload[8] is %x,payload[9] is %x\n",payload[8],payload[9]);
		//bpfprint("payload[10] is %x,payload[11] is %x\n",payload[10],payload[11]);
		//bpfprint("payload[19] is %x,payload[20] is %x\n",payload[19],payload[20]);
		/*bpfprint("%x\n",payload[20]);
		bpfprint("%x\n",payload[21]);
		bpfprint("%x\n",payload[22]);*/
		//bpfprint("xrc_tcp_hdr->tsv is %x\n",xrc_tcp_hdr->tsv);
		//bpfprint("data[0] is %x\n",xrc_tcp_hdr->data[0]);
		if(payload[20]=='g'&&payload[21]=='e'&&payload[22]=='t'){ // This is a GET request
			//bpfprint("This is a redis get!\n");
			// //
			unsigned int mid;
			memcpy(tmp_mac, eth->h_source, ETH_ALEN);
			memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
			memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

			tmp_ip = ip->saddr;
			ip->saddr = ip->daddr;//0a00_000a	//with 4500 4006 4000
			ip->daddr = tmp_ip;//0a00_0003
			ip->tot_len = 0x3d00;//003d

///////////////////////////////////
			ip->id =  __constant_htons(16218); // just change this!!
///////////////////////////////////

			mid = __constant_htonl((ip->saddr & 0x0000ffff)<<16) + __constant_htonl((ip->saddr & 0xffff0000)) + __constant_htonl((ip->daddr & 0x0000ffff)<<16) + __constant_htonl((ip->daddr & 0xffff0000)) + __constant_htons(ip->tot_len) + __constant_htons(ip->id) + 50438;	


			ip->check = ~((__be16)__constant_htonl((mid & 0x0000ffff)<<16) + __constant_htonl((mid & 0xffff0000))); // auto compute!
			
			tmp_port = tcp->source;
			tcp->source = tcp->dest;
			tcp->dest = tmp_port;
			//bpfprint("port:%d\n",__constant_htons(tcp->dest));
			tmp_seqnum = tcp->seq;
			tcp->seq = tcp->ack_seq; // auto
			//bpfprint("tmp_seqnum:%x\n",tmp_seqnum);
			//bpfprint("__constant_htonl:%d\n",__constant_htonl(tmp_seqnum));
			//bpfprint("__constant_ntohl:%x\n",__constant_ntohl(__constant_htonl(tmp_seqnum) + 21));
			tcp->ack_seq = __constant_ntohl(__constant_htonl(tmp_seqnum) + 21); // auto
			tcp->window = 0xfd01;
			/*bpfprint("tcp->seq_front: %x\n",(tcp->seq & 0xffff0000));
			bpfprint("tcp->seq_back: %x\n",(tcp->seq & 0x0000ffff)<<16);
			bpfprint("tcp->ack_seq_front: %x\n",(tcp->ack_seq & 0xffff0000));
			bpfprint("tcp->ack_seq_back: %x\n",(tcp->ack_seq & 0x0000ffff)<<16);*/

			tmp_tsv = xrc_tcp_hdr->tsv; // to be optimized.
			xrc_tcp_hdr->tsv = __constant_ntohl(__constant_htonl(xrc_tcp_hdr->tsv_r) + 2000);
			xrc_tcp_hdr->tsv_r = tmp_tsv;
			//bpfprint("tsv_r_front: %x\n",(xrc_tcp_hdr->tsv_r & 0xffff0000));
			//bpfprint("tsv_r_front: %d\n",__constant_htonl((xrc_tcp_hdr->tsv_r & 0xffff0000))); // done!
			//bpfprint("tsv_r_back: %x\n",(xrc_tcp_hdr->tsv_r & 0x0000ffff)<<16);
			//bpfprint("tsv_r_back: %d\n",__constant_htonl((xrc_tcp_hdr->tsv_r & 0x0000ffff)<<16)); // done!

			//bpfprint("tsv_front: %x\n",(xrc_tcp_hdr->tsv & 0xffff0000));
			//bpfprint("tsv_back: %x\n",(xrc_tcp_hdr->tsv & 0x0000ffff)<<16);
			mid = 0;
			mid = __constant_htonl((xrc_tcp_hdr->tsv_r & 0x0000ffff)<<16) + __constant_htonl((xrc_tcp_hdr->tsv_r & 0xffff0000)) + __constant_htonl((xrc_tcp_hdr->tsv & 0x0000ffff)<<16) + __constant_htonl((xrc_tcp_hdr->tsv & 0xffff0000)) + __constant_htonl((tcp->seq & 0x0000ffff)<<16) + __constant_htonl((tcp->seq & 0xffff0000)) + __constant_htonl((tcp->ack_seq & 0x0000ffff)<<16) + __constant_htonl((tcp->ack_seq & 0xffff0000)) + __constant_htons(tcp->dest) + 117760;			
			//bpfprint("check out mid: %d\n",mid);
			//bpfprint("check out mid: %x\n",__constant_ntohl(mid));
			//bpfprint("check out mid_test: %x\n",__constant_htonl((mid & 0x0000ffff)<<16) + __constant_htonl((mid & 0xffff0000)));
			//bpfprint("check out mid_test: %x\n",~((__be16)__constant_htonl((mid & 0x0000ffff)<<16) + __constant_htonl((mid & 0xffff0000))));
			

			xrc_tcp_hdr->data[0] = '$';
			xrc_tcp_hdr->data[1] = '3';
			xrc_tcp_hdr->data[2] = 0x0d;
			xrc_tcp_hdr->data[3] = 0x0a;
			xrc_tcp_hdr->data[4] = 'l';
			xrc_tcp_hdr->data[5] = 'o';
			xrc_tcp_hdr->data[6] = 'l';
			xrc_tcp_hdr->data[7] = 0x0d;
			xrc_tcp_hdr->data[8] = 0x0a; // static for now...
			
			tcp->check = ~((__be16)__constant_htonl((mid & 0x0000ffff)<<16) + __constant_htonl((mid & 0xffff0000))); // auto compute!
			//bpfprint("check out checksum: %x\n",tcp->check);


			bpf_xdp_adjust_tail(ctx, -12);
			//bpfprint("pkt TX away.\n\n");
			return XDP_TX;
		} else {
			//bpfprint("Normal TCP pkt...\n");
			//bpfprint("pkt PASS to kernel.\n\n");
			return XDP_PASS;
		}
	}
	return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
