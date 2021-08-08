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
test_map = {
        .type        = BPF_MAP_TYPE_HASH,
        .key_size    = sizeof(unsigned int),
        .value_size  = sizeof(unsigned int),
        .max_entries = 10000,
};

struct bpf_map_def SEC("maps")
cnt_map = {
        .type        = BPF_MAP_TYPE_HASH,
        .key_size    = sizeof(unsigned int),
        .value_size  = sizeof(unsigned int),
        .max_entries = 10,
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
    int payload_len = 520;   /// change payload len here!
    be16 ip_totlen_old;
    be16 dport;

    unsigned char tmp_mac[ETH_ALEN];
    be32 tmp_ip;
    be16 tmp_port;
    be32 tmp_seqnum;

    be32 tmp_tsv;

    unsigned int key = 0;
    unsigned int *value;

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
    if (payload + 520 <= data_end) {
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
            payload[1] = '5';   /// if you change data, change here!
            payload[2] = '1';
            payload[3] = '2';
            payload[4] = 0x0d;
            payload[5] = 0x0a;
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
            payload[37] = 'e';
            payload[38] = 'e';
            payload[39] = 'e';
            payload[40] = 'e';
            payload[41] = 'e';
            payload[42] = 'e';
            payload[43] = 'e';
            payload[44] = 'e';
            payload[45] = 'e';
            payload[46] = 'e';
            payload[47] = 'e';
            payload[48] = 'e';
            payload[49] = 'e';
            payload[50] = 'e';
            payload[51] = 'e';
            payload[52] = 'e';
            payload[53] = 'e';
            payload[54] = 'e';
            payload[55] = 'e';
            payload[56] = 'e';
            payload[57] = 'e';
            payload[58] = 'e';
            payload[59] = 'e';
            payload[60] = 'e';
            payload[61] = 'e';
            payload[62] = 'e';
            payload[63] = 'e';
            payload[64] = 'e';
            payload[65] = 'e';
            payload[66] = 'e';
            payload[67] = 'e';
            payload[68] = 'e';
            payload[69] = 'e';
            payload[70] = 'e';
            payload[71] = 'e';
            payload[72] = 'e';
            payload[73] = 'e';
            payload[74] = 'e';
            payload[75] = 'e';
            payload[76] = 'e';
            payload[77] = 'e';
            payload[78] = 'e';
            payload[79] = 'e';
            payload[80] = 'e';
            payload[81] = 'e';
            payload[82] = 'e';
            payload[83] = 'e';
            payload[84] = 'e';
            payload[85] = 'e';
            payload[86] = 'e';
            payload[87] = 'e';
            payload[88] = 'e';
            payload[89] = 'e';
            payload[90] = 'e';
            payload[91] = 'e';
            payload[92] = 'e';
            payload[93] = 'e';
            payload[94] = 'e';
            payload[95] = 'e';
            payload[96] = 'e';
            payload[97] = 'e';
            payload[98] = 'e';
            payload[99] = 'e';
            payload[100] = 'e';
            payload[101] = 'e';
            payload[102] = 'e';
            payload[103] = 'e';
            payload[104] = 'e';
            payload[105] = 'e';
            payload[106] = 'e';
            payload[107] = 'e';
            payload[108] = 'e';
            payload[109] = 'e';
            payload[110] = 'e';
            payload[111] = 'e';
            payload[112] = 'e';
            payload[113] = 'e';
            payload[114] = 'e';
            payload[115] = 'e';
            payload[116] = 'e';
            payload[117] = 'e';
            payload[118] = 'e';
            payload[119] = 'e';
            payload[120] = 'e';
            payload[121] = 'e';
            payload[122] = 'e';
            payload[123] = 'e';
            payload[124] = 'e';
            payload[125] = 'e';
            payload[126] = 'e';
            payload[127] = 'e';
            payload[128] = 'e';
            payload[129] = 'e';
            payload[130] = 'e';
            payload[131] = 'e';
            payload[132] = 'e';
            payload[133] = 'e';
            payload[134] = 'e';
            payload[135] = 'e';
            payload[136] = 'e';
            payload[137] = 'e';
            payload[138] = 'e';
            payload[139] = 'e';
            payload[140] = 'e';
            payload[141] = 'e';
            payload[142] = 'e';
            payload[143] = 'e';
            payload[144] = 'e';
            payload[145] = 'e';
            payload[146] = 'e';
            payload[147] = 'e';
            payload[148] = 'e';
            payload[149] = 'e';
            payload[150] = 'e';
            payload[151] = 'e';
            payload[152] = 'e';
            payload[153] = 'e';
            payload[154] = 'e';
            payload[155] = 'e';
            payload[156] = 'e';
            payload[157] = 'e';
            payload[158] = 'e';
            payload[159] = 'e';
            payload[160] = 'e';
            payload[161] = 'e';
            payload[162] = 'e';
            payload[163] = 'e';
            payload[164] = 'e';
            payload[165] = 'e';
            payload[166] = 'e';
            payload[167] = 'e';
            payload[168] = 'e';
            payload[169] = 'e';
            payload[170] = 'e';
            payload[171] = 'e';
            payload[172] = 'e';
            payload[173] = 'e';
            payload[174] = 'e';
            payload[175] = 'e';
            payload[176] = 'e';
            payload[177] = 'e';
            payload[178] = 'e';
            payload[179] = 'e';
            payload[180] = 'e';
            payload[181] = 'e';
            payload[182] = 'e';
            payload[183] = 'e';
            payload[184] = 'e';
            payload[185] = 'e';
            payload[186] = 'e';
            payload[187] = 'e';
            payload[188] = 'e';
            payload[189] = 'e';
            payload[190] = 'e';
            payload[191] = 'e';
            payload[192] = 'e';
            payload[193] = 'e';
            payload[194] = 'e';
            payload[195] = 'e';
            payload[196] = 'e';
            payload[197] = 'e';
            payload[198] = 'e';
            payload[199] = 'e';
            payload[200] = 'e';
            payload[201] = 'e';
            payload[202] = 'e';
            payload[203] = 'e';
            payload[204] = 'e';
            payload[205] = 'e';
            payload[206] = 'e';
            payload[207] = 'e';
            payload[208] = 'e';
            payload[209] = 'e';
            payload[210] = 'e';
            payload[211] = 'e';
            payload[212] = 'e';
            payload[213] = 'e';
            payload[214] = 'e';
            payload[215] = 'e';
            payload[216] = 'e';
            payload[217] = 'e';
            payload[218] = 'e';
            payload[219] = 'e';
            payload[220] = 'e';
            payload[221] = 'e';
            payload[222] = 'e';
            payload[223] = 'e';
            payload[224] = 'e';
            payload[225] = 'e';
            payload[226] = 'e';
            payload[227] = 'e';
            payload[228] = 'e';
            payload[229] = 'e';
            payload[230] = 'e';
            payload[231] = 'e';
            payload[232] = 'e';
            payload[233] = 'e';
            payload[234] = 'e';
            payload[235] = 'e';
            payload[236] = 'e';
            payload[237] = 'e';
            payload[238] = 'e';
            payload[239] = 'e';
            payload[240] = 'e';
            payload[241] = 'e';
            payload[242] = 'e';
            payload[243] = 'e';
            payload[244] = 'e';
            payload[245] = 'e';
            payload[246] = 'e';
            payload[247] = 'e';
            payload[248] = 'e';
            payload[249] = 'e';
            payload[250] = 'e';
            payload[251] = 'e';
            payload[252] = 'e';
            payload[253] = 'e';
            payload[254] = 'e';
            payload[255] = 'e';
            payload[256] = 'e';
            payload[257] = 'e';
            payload[258] = 'e';
            payload[259] = 'e';
            payload[260] = 'e';
            payload[261] = 'e';
            payload[262] = 'e';
            payload[263] = 'e';
            payload[264] = 'e';
            payload[265] = 'e';
            payload[266] = 'e';
            payload[267] = 'e';
            payload[268] = 'e';
            payload[269] = 'e';
            payload[270] = 'e';
            payload[271] = 'e';
            payload[272] = 'e';
            payload[273] = 'e';
            payload[274] = 'e';
            payload[275] = 'e';
            payload[276] = 'e';
            payload[277] = 'e';
            payload[278] = 'e';
            payload[279] = 'e';
            payload[280] = 'e';
            payload[281] = 'e';
            payload[282] = 'e';
            payload[283] = 'e';
            payload[284] = 'e';
            payload[285] = 'e';
            payload[286] = 'e';
            payload[287] = 'e';
            payload[288] = 'e';
            payload[289] = 'e';
            payload[290] = 'e';
            payload[291] = 'e';
            payload[292] = 'e';
            payload[293] = 'e';
            payload[294] = 'e';
            payload[295] = 'e';
            payload[296] = 'e';
            payload[297] = 'e';
            payload[298] = 'e';
            payload[299] = 'e';
            payload[300] = 'e';
            payload[301] = 'e';
            payload[302] = 'e';
            payload[303] = 'e';
            payload[304] = 'e';
            payload[305] = 'e';
            payload[306] = 'e';
            payload[307] = 'e';
            payload[308] = 'e';
            payload[309] = 'e';
            payload[310] = 'e';
            payload[311] = 'e';
            payload[312] = 'e';
            payload[313] = 'e';
            payload[314] = 'e';
            payload[315] = 'e';
            payload[316] = 'e';
            payload[317] = 'e';
            payload[318] = 'e';
            payload[319] = 'e';
            payload[320] = 'e';
            payload[321] = 'e';
            payload[322] = 'e';
            payload[323] = 'e';
            payload[324] = 'e';
            payload[325] = 'e';
            payload[326] = 'e';
            payload[327] = 'e';
            payload[328] = 'e';
            payload[329] = 'e';
            payload[330] = 'e';
            payload[331] = 'e';
            payload[332] = 'e';
            payload[333] = 'e';
            payload[334] = 'e';
            payload[335] = 'e';
            payload[336] = 'e';
            payload[337] = 'e';
            payload[338] = 'e';
            payload[339] = 'e';
            payload[340] = 'e';
            payload[341] = 'e';
            payload[342] = 'e';
            payload[343] = 'e';
            payload[344] = 'e';
            payload[345] = 'e';
            payload[346] = 'e';
            payload[347] = 'e';
            payload[348] = 'e';
            payload[349] = 'e';
            payload[350] = 'e';
            payload[351] = 'e';
            payload[352] = 'e';
            payload[353] = 'e';
            payload[354] = 'e';
            payload[355] = 'e';
            payload[356] = 'e';
            payload[357] = 'e';
            payload[358] = 'e';
            payload[359] = 'e';
            payload[360] = 'e';
            payload[361] = 'e';
            payload[362] = 'e';
            payload[363] = 'e';
            payload[364] = 'e';
            payload[365] = 'e';
            payload[366] = 'e';
            payload[367] = 'e';
            payload[368] = 'e';
            payload[369] = 'e';
            payload[370] = 'e';
            payload[371] = 'e';
            payload[372] = 'e';
            payload[373] = 'e';
            payload[374] = 'e';
            payload[375] = 'e';
            payload[376] = 'e';
            payload[377] = 'e';
            payload[378] = 'e';
            payload[379] = 'e';
            payload[380] = 'e';
            payload[381] = 'e';
            payload[382] = 'e';
            payload[383] = 'e';
            payload[384] = 'e';
            payload[385] = 'e';
            payload[386] = 'e';
            payload[387] = 'e';
            payload[388] = 'e';
            payload[389] = 'e';
            payload[390] = 'e';
            payload[391] = 'e';
            payload[392] = 'e';
            payload[393] = 'e';
            payload[394] = 'e';
            payload[395] = 'e';
            payload[396] = 'e';
            payload[397] = 'e';
            payload[398] = 'e';
            payload[399] = 'e';
            payload[400] = 'e';
            payload[401] = 'e';
            payload[402] = 'e';
            payload[403] = 'e';
            payload[404] = 'e';
            payload[405] = 'e';
            payload[406] = 'e';
            payload[407] = 'e';
            payload[408] = 'e';
            payload[409] = 'e';
            payload[410] = 'e';
            payload[411] = 'e';
            payload[412] = 'e';
            payload[413] = 'e';
            payload[414] = 'e';
            payload[415] = 'e';
            payload[416] = 'e';
            payload[417] = 'e';
            payload[418] = 'e';
            payload[419] = 'e';
            payload[420] = 'e';
            payload[421] = 'e';
            payload[422] = 'e';
            payload[423] = 'e';
            payload[424] = 'e';
            payload[425] = 'e';
            payload[426] = 'e';
            payload[427] = 'e';
            payload[428] = 'e';
            payload[429] = 'e';
            payload[430] = 'e';
            payload[431] = 'e';
            payload[432] = 'e';
            payload[433] = 'e';
            payload[434] = 'e';
            payload[435] = 'e';
            payload[436] = 'e';
            payload[437] = 'e';
            payload[438] = 'e';
            payload[439] = 'e';
            payload[440] = 'e';
            payload[441] = 'e';
            payload[442] = 'e';
            payload[443] = 'e';
            payload[444] = 'e';
            payload[445] = 'e';
            payload[446] = 'e';
            payload[447] = 'e';
            payload[448] = 'e';
            payload[449] = 'e';
            payload[450] = 'e';
            payload[451] = 'e';
            payload[452] = 'e';
            payload[453] = 'e';
            payload[454] = 'e';
            payload[455] = 'e';
            payload[456] = 'e';
            payload[457] = 'e';
            payload[458] = 'e';
            payload[459] = 'e';
            payload[460] = 'e';
            payload[461] = 'e';
            payload[462] = 'e';
            payload[463] = 'e';
            payload[464] = 'e';
            payload[465] = 'e';
            payload[466] = 'e';
            payload[467] = 'e';
            payload[468] = 'e';
            payload[469] = 'e';
            payload[470] = 'e';
            payload[471] = 'e';
            payload[472] = 'e';
            payload[473] = 'e';
            payload[474] = 'e';
            payload[475] = 'e';
            payload[476] = 'e';
            payload[477] = 'e';
            payload[478] = 'e';
            payload[479] = 'e';
            payload[480] = 'e';
            payload[481] = 'e';
            payload[482] = 'e';
            payload[483] = 'e';
            payload[484] = 'e';
            payload[485] = 'e';
            payload[486] = 'e';
            payload[487] = 'e';
            payload[488] = 'e';
            payload[489] = 'e';
            payload[490] = 'e';
            payload[491] = 'e';
            payload[492] = 'e';
            payload[493] = 'e';
            payload[494] = 'e';
            payload[495] = 'e';
            payload[496] = 'e';
            payload[497] = 'e';
            payload[498] = 'e';
            payload[499] = 'e';
            payload[500] = 'e';
            payload[501] = 'e';
            payload[502] = 'e';
            payload[503] = 'e';
            payload[504] = 'e';
            payload[505] = 'e';
            payload[506] = 'e';
            payload[507] = 'e';
            payload[508] = 'e';
            payload[509] = 'e';
            payload[510] = 'e';
            payload[511] = 'e';
            payload[512] = 'e';
            payload[513] = 'e';
            payload[514] = 'e';
            payload[515] = 'e';
            payload[516] = 'e';
            payload[517] = 'e';
            payload[518] = 0x0d;
            payload[519] = 0x0a; // static for now...
            tcp->check = 0;
            if(payload + payload_len + 1 <= data_end){
                tcp->check = compute_tcp_checksum(ip, tcp, tcphdr_ops, payload, payload_len);
            }
            key = tcp->ack_seq;
            tmp_tsv = 11;
            bpf_map_update_elem(&test_map, &key, &tmp_tsv, BPF_ANY);

            bpf_xdp_adjust_tail(ctx, -(ip_totlen_old - 52 - payload_len));

	    key = 0;
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


            return XDP_TX;
        } else { // Not a GET
            return XDP_PASS;
        }
    }// end if (payload + 11 <= data_end)

    key = tcp->seq;
    value = bpf_map_lookup_elem(&test_map, &key);

    if(value){
        bpf_map_delete_elem(&test_map, &key);
        return XDP_DROP;
    }


    return XDP_PASS;
}

char _license[]
SEC("license") = "GPL";
