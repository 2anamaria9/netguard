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

void scan_detector_report(const scan_detector_t *sd, uint64_t threshold) {
    src_entry *entry, *tmp;
    int ok = 0;
    HASH_ITER(hh, sd->sources, entry, tmp) {
        uint64_t ports = hll_estimate(&entry->h);
        if (ports >= threshold) {
            if (!ok) {
                printf("--- Possible PORT SCANS (distinct ports >= %llu) ---\n", (unsigned long long)threshold);
                ok = 1;
            }
            char s[INET_ADDRSTRLEN];
            ip_to_str(entry->src_ip, s, sizeof(s));
            printf("  [!] %-16s ~%llu distinct ports\n", s, (unsigned long long)ports);
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