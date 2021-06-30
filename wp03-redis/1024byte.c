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
    int payload_len = 1033;   /// change payload len here!
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
    if (payload + 1033 <= data_end) {
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
            payload[1] = '1';   /// if you change data, change here!
            payload[2] = '0';
            payload[3] = '2';
            payload[4] = '4';
            payload[5] = 0x0d;
            payload[6] = 0x0a;
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
            payload[518] = 'e';
            payload[519] = 'e';
            payload[520] = 'e';
            payload[521] = 'e';
            payload[522] = 'e';
            payload[523] = 'e';
            payload[524] = 'e';
            payload[525] = 'e';
            payload[526] = 'e';
            payload[527] = 'e';
            payload[528] = 'e';
            payload[529] = 'e';
            payload[530] = 'e';
            payload[531] = 'e';
            payload[532] = 'e';
            payload[533] = 'e';
            payload[534] = 'e';
            payload[535] = 'e';
            payload[536] = 'e';
            payload[537] = 'e';
            payload[538] = 'e';
            payload[539] = 'e';
            payload[540] = 'e';
            payload[541] = 'e';
            payload[542] = 'e';
            payload[543] = 'e';
            payload[544] = 'e';
            payload[545] = 'e';
            payload[546] = 'e';
            payload[547] = 'e';
            payload[548] = 'e';
            payload[549] = 'e';
            payload[550] = 'e';
            payload[551] = 'e';
            payload[552] = 'e';
            payload[553] = 'e';
            payload[554] = 'e';
            payload[555] = 'e';
            payload[556] = 'e';
            payload[557] = 'e';
            payload[558] = 'e';
            payload[559] = 'e';
            payload[560] = 'e';
            payload[561] = 'e';
            payload[562] = 'e';
            payload[563] = 'e';
            payload[564] = 'e';
            payload[565] = 'e';
            payload[566] = 'e';
            payload[567] = 'e';
            payload[568] = 'e';
            payload[569] = 'e';
            payload[570] = 'e';
            payload[571] = 'e';
            payload[572] = 'e';
            payload[573] = 'e';
            payload[574] = 'e';
            payload[575] = 'e';
            payload[576] = 'e';
            payload[577] = 'e';
            payload[578] = 'e';
            payload[579] = 'e';
            payload[580] = 'e';
            payload[581] = 'e';
            payload[582] = 'e';
            payload[583] = 'e';
            payload[584] = 'e';
            payload[585] = 'e';
            payload[586] = 'e';
            payload[587] = 'e';
            payload[588] = 'e';
            payload[589] = 'e';
            payload[590] = 'e';
            payload[591] = 'e';
            payload[592] = 'e';
            payload[593] = 'e';
            payload[594] = 'e';
            payload[595] = 'e';
            payload[596] = 'e';
            payload[597] = 'e';
            payload[598] = 'e';
            payload[599] = 'e';
            payload[600] = 'e';
            payload[601] = 'e';
            payload[602] = 'e';
            payload[603] = 'e';
            payload[604] = 'e';
            payload[605] = 'e';
            payload[606] = 'e';
            payload[607] = 'e';
            payload[608] = 'e';
            payload[609] = 'e';
            payload[610] = 'e';
            payload[611] = 'e';
            payload[612] = 'e';
            payload[613] = 'e';
            payload[614] = 'e';
            payload[615] = 'e';
            payload[616] = 'e';
            payload[617] = 'e';
            payload[618] = 'e';
            payload[619] = 'e';
            payload[620] = 'e';
            payload[621] = 'e';
            payload[622] = 'e';
            payload[623] = 'e';
            payload[624] = 'e';
            payload[625] = 'e';
            payload[626] = 'e';
            payload[627] = 'e';
            payload[628] = 'e';
            payload[629] = 'e';
            payload[630] = 'e';
            payload[631] = 'e';
            payload[632] = 'e';
            payload[633] = 'e';
            payload[634] = 'e';
            payload[635] = 'e';
            payload[636] = 'e';
            payload[637] = 'e';
            payload[638] = 'e';
            payload[639] = 'e';
            payload[640] = 'e';
            payload[641] = 'e';
            payload[642] = 'e';
            payload[643] = 'e';
            payload[644] = 'e';
            payload[645] = 'e';
            payload[646] = 'e';
            payload[647] = 'e';
            payload[648] = 'e';
            payload[649] = 'e';
            payload[650] = 'e';
            payload[651] = 'e';
            payload[652] = 'e';
            payload[653] = 'e';
            payload[654] = 'e';
            payload[655] = 'e';
            payload[656] = 'e';
            payload[657] = 'e';
            payload[658] = 'e';
            payload[659] = 'e';
            payload[660] = 'e';
            payload[661] = 'e';
            payload[662] = 'e';
            payload[663] = 'e';
            payload[664] = 'e';
            payload[665] = 'e';
            payload[666] = 'e';
            payload[667] = 'e';
            payload[668] = 'e';
            payload[669] = 'e';
            payload[670] = 'e';
            payload[671] = 'e';
            payload[672] = 'e';
            payload[673] = 'e';
            payload[674] = 'e';
            payload[675] = 'e';
            payload[676] = 'e';
            payload[677] = 'e';
            payload[678] = 'e';
            payload[679] = 'e';
            payload[680] = 'e';
            payload[681] = 'e';
            payload[682] = 'e';
            payload[683] = 'e';
            payload[684] = 'e';
            payload[685] = 'e';
            payload[686] = 'e';
            payload[687] = 'e';
            payload[688] = 'e';
            payload[689] = 'e';
            payload[690] = 'e';
            payload[691] = 'e';
            payload[692] = 'e';
            payload[693] = 'e';
            payload[694] = 'e';
            payload[695] = 'e';
            payload[696] = 'e';
            payload[697] = 'e';
            payload[698] = 'e';
            payload[699] = 'e';
            payload[700] = 'e';
            payload[701] = 'e';
            payload[702] = 'e';
            payload[703] = 'e';
            payload[704] = 'e';
            payload[705] = 'e';
            payload[706] = 'e';
            payload[707] = 'e';
            payload[708] = 'e';
            payload[709] = 'e';
            payload[710] = 'e';
            payload[711] = 'e';
            payload[712] = 'e';
            payload[713] = 'e';
            payload[714] = 'e';
            payload[715] = 'e';
            payload[716] = 'e';
            payload[717] = 'e';
            payload[718] = 'e';
            payload[719] = 'e';
            payload[720] = 'e';
            payload[721] = 'e';
            payload[722] = 'e';
            payload[723] = 'e';
            payload[724] = 'e';
            payload[725] = 'e';
            payload[726] = 'e';
            payload[727] = 'e';
            payload[728] = 'e';
            payload[729] = 'e';
            payload[730] = 'e';
            payload[731] = 'e';
            payload[732] = 'e';
            payload[733] = 'e';
            payload[734] = 'e';
            payload[735] = 'e';
            payload[736] = 'e';
            payload[737] = 'e';
            payload[738] = 'e';
            payload[739] = 'e';
            payload[740] = 'e';
            payload[741] = 'e';
            payload[742] = 'e';
            payload[743] = 'e';
            payload[744] = 'e';
            payload[745] = 'e';
            payload[746] = 'e';
            payload[747] = 'e';
            payload[748] = 'e';
            payload[749] = 'e';
            payload[750] = 'e';
            payload[751] = 'e';
            payload[752] = 'e';
            payload[753] = 'e';
            payload[754] = 'e';
            payload[755] = 'e';
            payload[756] = 'e';
            payload[757] = 'e';
            payload[758] = 'e';
            payload[759] = 'e';
            payload[760] = 'e';
            payload[761] = 'e';
            payload[762] = 'e';
            payload[763] = 'e';
            payload[764] = 'e';
            payload[765] = 'e';
            payload[766] = 'e';
            payload[767] = 'e';
            payload[768] = 'e';
            payload[769] = 'e';
            payload[770] = 'e';
            payload[771] = 'e';
            payload[772] = 'e';
            payload[773] = 'e';
            payload[774] = 'e';
            payload[775] = 'e';
            payload[776] = 'e';
            payload[777] = 'e';
            payload[778] = 'e';
            payload[779] = 'e';
            payload[780] = 'e';
            payload[781] = 'e';
            payload[782] = 'e';
            payload[783] = 'e';
            payload[784] = 'e';
            payload[785] = 'e';
            payload[786] = 'e';
            payload[787] = 'e';
            payload[788] = 'e';
            payload[789] = 'e';
            payload[790] = 'e';
            payload[791] = 'e';
            payload[792] = 'e';
            payload[793] = 'e';
            payload[794] = 'e';
            payload[795] = 'e';
            payload[796] = 'e';
            payload[797] = 'e';
            payload[798] = 'e';
            payload[799] = 'e';
            payload[800] = 'e';
            payload[801] = 'e';
            payload[802] = 'e';
            payload[803] = 'e';
            payload[804] = 'e';
            payload[805] = 'e';
            payload[806] = 'e';
            payload[807] = 'e';
            payload[808] = 'e';
            payload[809] = 'e';
            payload[810] = 'e';
            payload[811] = 'e';
            payload[812] = 'e';
            payload[813] = 'e';
            payload[814] = 'e';
            payload[815] = 'e';
            payload[816] = 'e';
            payload[817] = 'e';
            payload[818] = 'e';
            payload[819] = 'e';
            payload[820] = 'e';
            payload[821] = 'e';
            payload[822] = 'e';
            payload[823] = 'e';
            payload[824] = 'e';
            payload[825] = 'e';
            payload[826] = 'e';
            payload[827] = 'e';
            payload[828] = 'e';
            payload[829] = 'e';
            payload[830] = 'e';
            payload[831] = 'e';
            payload[832] = 'e';
            payload[833] = 'e';
            payload[834] = 'e';
            payload[835] = 'e';
            payload[836] = 'e';
            payload[837] = 'e';
            payload[838] = 'e';
            payload[839] = 'e';
            payload[840] = 'e';
            payload[841] = 'e';
            payload[842] = 'e';
            payload[843] = 'e';
            payload[844] = 'e';
            payload[845] = 'e';
            payload[846] = 'e';
            payload[847] = 'e';
            payload[848] = 'e';
            payload[849] = 'e';
            payload[850] = 'e';
            payload[851] = 'e';
            payload[852] = 'e';
            payload[853] = 'e';
            payload[854] = 'e';
            payload[855] = 'e';
            payload[856] = 'e';
            payload[857] = 'e';
            payload[858] = 'e';
            payload[859] = 'e';
            payload[860] = 'e';
            payload[861] = 'e';
            payload[862] = 'e';
            payload[863] = 'e';
            payload[864] = 'e';
            payload[865] = 'e';
            payload[866] = 'e';
            payload[867] = 'e';
            payload[868] = 'e';
            payload[869] = 'e';
            payload[870] = 'e';
            payload[871] = 'e';
            payload[872] = 'e';
            payload[873] = 'e';
            payload[874] = 'e';
            payload[875] = 'e';
            payload[876] = 'e';
            payload[877] = 'e';
            payload[878] = 'e';
            payload[879] = 'e';
            payload[880] = 'e';
            payload[881] = 'e';
            payload[882] = 'e';
            payload[883] = 'e';
            payload[884] = 'e';
            payload[885] = 'e';
            payload[886] = 'e';
            payload[887] = 'e';
            payload[888] = 'e';
            payload[889] = 'e';
            payload[890] = 'e';
            payload[891] = 'e';
            payload[892] = 'e';
            payload[893] = 'e';
            payload[894] = 'e';
            payload[895] = 'e';
            payload[896] = 'e';
            payload[897] = 'e';
            payload[898] = 'e';
            payload[899] = 'e';
            payload[900] = 'e';
            payload[901] = 'e';
            payload[902] = 'e';
            payload[903] = 'e';
            payload[904] = 'e';
            payload[905] = 'e';
            payload[906] = 'e';
            payload[907] = 'e';
            payload[908] = 'e';
            payload[909] = 'e';
            payload[910] = 'e';
            payload[911] = 'e';
            payload[912] = 'e';
            payload[913] = 'e';
            payload[914] = 'e';
            payload[915] = 'e';
            payload[916] = 'e';
            payload[917] = 'e';
            payload[918] = 'e';
            payload[919] = 'e';
            payload[920] = 'e';
            payload[921] = 'e';
            payload[922] = 'e';
            payload[923] = 'e';
            payload[924] = 'e';
            payload[925] = 'e';
            payload[926] = 'e';
            payload[927] = 'e';
            payload[928] = 'e';
            payload[929] = 'e';
            payload[930] = 'e';
            payload[931] = 'e';
            payload[932] = 'e';
            payload[933] = 'e';
            payload[934] = 'e';
            payload[935] = 'e';
            payload[936] = 'e';
            payload[937] = 'e';
            payload[938] = 'e';
            payload[939] = 'e';
            payload[940] = 'e';
            payload[941] = 'e';
            payload[942] = 'e';
            payload[943] = 'e';
            payload[944] = 'e';
            payload[945] = 'e';
            payload[946] = 'e';
            payload[947] = 'e';
            payload[948] = 'e';
            payload[949] = 'e';
            payload[950] = 'e';
            payload[951] = 'e';
            payload[952] = 'e';
            payload[953] = 'e';
            payload[954] = 'e';
            payload[955] = 'e';
            payload[956] = 'e';
            payload[957] = 'e';
            payload[958] = 'e';
            payload[959] = 'e';
            payload[960] = 'e';
            payload[961] = 'e';
            payload[962] = 'e';
            payload[963] = 'e';
            payload[964] = 'e';
            payload[965] = 'e';
            payload[966] = 'e';
            payload[967] = 'e';
            payload[968] = 'e';
            payload[969] = 'e';
            payload[970] = 'e';
            payload[971] = 'e';
            payload[972] = 'e';
            payload[973] = 'e';
            payload[974] = 'e';
            payload[975] = 'e';
            payload[976] = 'e';
            payload[977] = 'e';
            payload[978] = 'e';
            payload[979] = 'e';
            payload[980] = 'e';
            payload[981] = 'e';
            payload[982] = 'e';
            payload[983] = 'e';
            payload[984] = 'e';
            payload[985] = 'e';
            payload[986] = 'e';
            payload[987] = 'e';
            payload[988] = 'e';
            payload[989] = 'e';
            payload[990] = 'e';
            payload[991] = 'e';
            payload[992] = 'e';
            payload[993] = 'e';
            payload[994] = 'e';
            payload[995] = 'e';
            payload[996] = 'e';
            payload[997] = 'e';
            payload[998] = 'e';
            payload[999] = 'e';
            payload[1000] = 'e';
            payload[1001] = 'e';
            payload[1002] = 'e';
            payload[1003] = 'e';
            payload[1004] = 'e';
            payload[1005] = 'e';
            payload[1006] = 'e';
            payload[1007] = 'e';
            payload[1008] = 'e';
            payload[1009] = 'e';
            payload[1010] = 'e';
            payload[1011] = 'e';
            payload[1012] = 'e';
            payload[1013] = 'e';
            payload[1014] = 'e';
            payload[1015] = 'e';
            payload[1016] = 'e';
            payload[1017] = 'e';
            payload[1018] = 'e';
            payload[1019] = 'e';
            payload[1020] = 'e';
            payload[1021] = 'e';
            payload[1022] = 'e';
            payload[1023] = 'e';
            payload[1024] = 'e';
            payload[1025] = 'e';
            payload[1026] = 'e';
            payload[1027] = 'e';
            payload[1028] = 'e';
            payload[1029] = 'e';
            payload[1030] = 'e';
            payload[1031] = 0x0d;
            payload[1032] = 0x0a; // static for now...
            tcp->check = 0;
            if(payload + payload_len + 1 <= data_end){
                tcp->check = compute_tcp_checksum(ip, tcp, tcphdr_ops, payload, payload_len);
            }
                        key = tcp->ack_seq;
            tmp_tsv = 11;
            bpf_map_update_elem(&test_map, &key, &tmp_tsv, BPF_ANY);

            bpf_xdp_adjust_tail(ctx, -(ip_totlen_old - 52 - payload_len));


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
