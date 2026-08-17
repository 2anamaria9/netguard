#include "../../include/detect/entropy.h"
#include "../../include/detect/entropy_detect.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int entropy_detector_init(entropy_detector_t *e) {
    e->port_counts = calloc(NUM_PORTS, sizeof(uint64_t));
    if (e->port_counts == NULL) {
        return -1;
    }
    cusum_init(&e->sum, 0.5, 3.0, 0.3);
    return 0;
}

void entropy_detector_run(entropy_detector_t *e, const flow_table *ft) {
    memset(e->port_counts, 0, NUM_PORTS * sizeof(uint64_t));
    flow_t *flow, *tmp;
    HASH_ITER(hh, ft->flows, flow, tmp) {
        uint16_t port = flow->key.dst_port;
        e->port_counts[port] += flow->packets; 
    }

    double ent = entropy(e->port_counts, NUM_PORTS);
    int res = cusum_update(&e->sum, ent);
    
    printf("--- Port-entropy: %.3f bits", ent);
    if (!e->sum.warmed_up)
        printf(" (calibrating)");
    printf("\n");

    if (res == 1) {
        printf("[!] ANOMALY: port entropy shifted UP (possible port scan)\n");
        cusum_reset(&e->sum);
    } else if (res == -1) {
        printf("[!] ANOMALY: port entropy shifted DOWN (possible DDoS)\n");
        cusum_reset(&e->sum);
    }
}

void entropy_detector_free(entropy_detector_t *e) {
    free(e->port_counts);
    e->port_counts = NULL;
}
