#ifndef ENGINE_H
#define ENGINE_H

#include <pcap.h>
#include "flow.h"
#include "sketch/cms.h"

typedef struct {
    flow_table *ft;
    count_min_sketch *c;
} packet_t;

int engine_run(pcap_t *handle, flow_table *ft, count_min_sketch *c, int report_interval, int flow_timeout);
void engine_stop(void);
void on_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

#endif