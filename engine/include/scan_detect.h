#ifndef SCAN_DETECT_H
#define SCAN_DETECT_H

#include <stdint.h>
#include "sketch/hll.h"
#include "sketch/cms.h"
#include "uthash.h"

typedef struct {
    uint32_t src_ip;
    hyperloglog h;
    UT_hash_handle hh;
} src_entry;

typedef struct {
    src_entry *sources;
    uint32_t prec;
} scan_detector_t;

void scan_detector_init(scan_detector_t *sd, uint32_t prec);
void scan_detector_add(scan_detector_t *sd, uint32_t src_ip, uint16_t dst_port);
void scan_detector_report(const scan_detector_t *sd, const count_min_sketch *c, uint64_t threshold);
void scan_detector_reset(scan_detector_t *sd);
void scan_detector_free(scan_detector_t *sd);

#endif