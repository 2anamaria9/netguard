#ifndef FLOW_H
#define FLOW_H

#include <stdint.h>
#include <time.h>
#include "../include/parse.h"
#include "../include/uthash.h"

typedef struct __attribute__((packed)) {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} flow_key;

typedef struct {
    flow_key key;
    uint64_t packets;         
    uint64_t bytes;       
    time_t   first_seen;      
    time_t   last_seen;       
    UT_hash_handle hh;
} flow_t;

typedef struct {
    flow_t *flows;
    uint64_t count;
} flow_table;

void flow_table_init(flow_table *ft);
void flow_table_update(flow_table *ft, const packet_info *p, time_t ts);
void flow_table_print_top(const flow_table *ft, int n);
void flow_table_free(flow_table *ft);

#endif
