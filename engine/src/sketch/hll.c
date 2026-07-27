#include "../../include/sketch/hll.h"
#include "../../include/hash.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// constants from Flajolet, "HyperLogLog"
#define ALPHA_NUM 0.7213
#define ALPHA_DEN 1.079
#define ALPHA_SMALL 0.709
#define RANGE_FACTOR 2.5

int hll_init(hyperloglog *h, uint32_t prec) {
    h->prec = prec;
    h->count = 1u << prec;
    h->registers = calloc(h->count, sizeof(uint8_t));

    if (h->registers == NULL) {
        return -1;
    }
    return 0;
}

void hll_add(hyperloglog *h, const void *key, size_t len) {
    uint64_t hash = fnv1a(key, len, 0);
    hash = hash_finalize(hash);
    uint32_t idx = (uint32_t)(hash >> (64 - h->prec));
    uint64_t rest = (hash << h->prec) | (1ULL << (h->prec - 1));
    uint8_t value = (uint8_t)(__builtin_clzll(rest) + 1);

    if (value > h->registers[idx]) {
        h->registers[idx] = value;
    }
}

uint64_t hll_estimate(const hyperloglog *h) {
    double m = (double)h->count;
    double alpha;
    if (h->count >= 128) {
        alpha = ALPHA_NUM / (1.0 + ALPHA_DEN / m);
    } else {
        alpha = ALPHA_SMALL;
    }

    double sum = 0.0;
    uint32_t zero_counter = 0;
    for (uint32_t i = 0; i < h->count; i++) {
        sum = sum + 1.0 / (double)(1ULL << h->registers[i]);
        if (h->registers[i] == 0) {
            zero_counter++;
        }
    }

    double estimate = alpha * m * m / sum;
    if (estimate <= 2.5 * m && zero_counter > 0) {
        estimate = m * log(m / (double)zero_counter);
    }
    return (uint64_t)(estimate + 0.5);
}

void hll_reset(hyperloglog *h) {
    memset(h->registers, 0, h->count * sizeof(uint8_t));
}

void hll_free(hyperloglog *h) {
    free(h->registers);
    h->registers = NULL;
}