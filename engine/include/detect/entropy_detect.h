#ifndef ENTROPY_DETECT_H
#define ENTROPY_DETECT_H

#include "../flow.h"
#include "cusum.h"
#include <stdint.h>

#define NUM_PORTS 65536

typedef struct{
    uint64_t *port_counts;
    cusum_t sum;
} entropy_detector_t;

int entropy_detector_init(entropy_detector_t *e);
void entropy_detector_run(entropy_detector_t *e, const flow_table *ft);
void entropy_detector_free(entropy_detector_t *e);

#endif
