#include "../include/flow.h"

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static int compare(const flow_t *a, const flow_t *b) {
    if (a->packets < b->packets) {
        return 1;
    }
    if (a->packets > b->packets) {
        return -1;
    }
    return 0;
}

void flow_table_init(flow_table *ft) {
    ft->flows = NULL;
    ft->count = 0;
}

void flow_table_update(flow_table *ft, const packet_info *p, time_t ts) {
    flow_key key;
    memset(&key, 0, sizeof(key));
    key.src_ip = p->src_ip;
    key.dst_ip = p->dst_ip;
    key.src_port = p->src_port;
    key.dst_port = p->dst_port;
    if (p->proto == PROTO_TCP) {
        key.proto = IPPROTO_TCP;
    } else {
        key.proto = IPPROTO_UDP;
    }

    flow_t *flow = NULL;
    HASH_FIND(hh, ft->flows, &key, sizeof(flow_key), flow);

    if (flow == NULL) {
        flow = calloc(1, sizeof(flow_t));
        if (flow == NULL) {
            return;
        }
        flow->key = key;
        flow->first_seen = ts;
        flow->packets = 0;
        flow->bytes = 0;

        HASH_ADD(hh, ft->flows, key, sizeof(flow_key), flow);
        ft->count++;
    }

    flow->packets++;
    flow->bytes = flow->bytes + p->length;
    flow->last_seen = ts;
}

void flow_table_print_top(const flow_table *ft, int n) {
    HASH_SORT(((flow_table *)ft)->flows, compare);

    printf("TOP FLOWS - %llu active", (unsigned long long)ft->count);

    int i = 0;
    flow_t *flow, *tmp;
    HASH_ITER(hh, ft->flows, flow, tmp) {
        if (i++ >= n) {
            break;
        }
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        ip_to_str(flow->key.src_ip, src, sizeof(src));
        ip_to_str(flow->key.dst_ip, dst, sizeof(dst));

        printf("  %-3s %s:%u -> %s:%u  | %llu pkts, %llu bytes\n",
               flow->key.proto == IPPROTO_TCP ? "TCP" : "UDP",
               src, flow->key.src_port,   
               dst, flow->key.dst_port, 
               (unsigned long long)flow->packets,
               (unsigned long long)flow->bytes);
    }
}

void flow_table_free(flow_table *ft) {
    flow_t *flow, *tmp;
    HASH_ITER(hh, ft->flows, flow, tmp) {
        HASH_DEL(ft->flows, flow);
        free(flow);
    }
    ft->flows = NULL;
    ft->count = 0;
}