#include "../include/scan_detect.h"
#include "../include/parse.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

void scan_detector_init(scan_detector_t *sd, uint32_t prec) {
    sd->sources = NULL;
    sd->prec = prec;
}

void scan_detector_add(scan_detector_t *sd, uint32_t src_ip, uint16_t dst_port) {
    src_entry *entry = NULL;
    HASH_FIND(hh, sd->sources, &src_ip, sizeof(uint32_t), entry);

    if (entry == NULL) {
        entry = calloc(1, sizeof(src_entry));
        if (entry == NULL) {
            return;
        }
        entry->src_ip = src_ip;
        if (hll_init(&entry->h, sd->prec) != 0) {
            free(entry);
            return;
        }
        HASH_ADD(hh, sd->sources, src_ip, sizeof(uint32_t), entry);
    }
    hll_add(&entry->h, &dst_port, sizeof(uint16_t));
}

void scan_detector_report(const scan_detector_t *sd, const count_min_sketch *c, uint64_t threshold) {
    src_entry *entry, *tmp;
    int ok = 0;
    HASH_ITER(hh, sd->sources, entry, tmp) {
        uint64_t ports = hll_estimate(&entry->h);
        if (ports >= threshold) {
            if (!ok) {
                printf("--- Possible SCANS / FLOODS (distinct ports >= %llu) ---\n", (unsigned long long)threshold);
                ok = 1;
            }

            uint64_t packets = cms_estimate(c, &entry->src_ip, sizeof(entry->src_ip));
            double ratio = 0;
            if (ports > 0) {
                ratio = (double)packets / (double)ports;
            }

            char s[INET_ADDRSTRLEN];
            ip_to_str(entry->src_ip, s, sizeof(s));
            
            if (ratio > 10) {
                printf("  [!] %-16s ~%llu ports, %llu pkts (%.1f pkts/port) -> FLOOD\n", 
                    s, 
                    (unsigned long long)ports, 
                    (unsigned long long)packets, 
                    ratio);
            } else {
                printf("  [!] %-16s ~%llu ports, %llu pkts (%.1f pkts/port) -> SCAN\n", 
                    s, 
                    (unsigned long long)ports, 
                    (unsigned long long)packets, 
                    ratio);
            }
        }
    }
}

void scan_detector_reset(scan_detector_t *sd) {
    src_entry *entry, *tmp;
    HASH_ITER(hh, sd->sources, entry, tmp) {
        HASH_DEL(sd->sources, entry);
        hll_free(&entry->h);
        free(entry);
    }
    sd->sources = NULL;
}

void scan_detector_free(scan_detector_t *sd) {
    scan_detector_reset(sd);
}