#include "../../include/sketch/cms.h"
#include "../../include/hash.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int cms_init(count_min_sketch *c, uint32_t n, uint32_t m) {
    c->n = n;
    c->m = m;
    c->matrix = calloc((size_t)n * m, sizeof(uint64_t));
    if (c->matrix == NULL)
        return -1;
    return 0;
}

static uint32_t column_for_row(const count_min_sketch *c, const void *key, size_t len, uint32_t row) {
    uint64_t hash = fnv1a(key, len, row);
    return (uint32_t)(hash % c->m);
}

void cms_add(count_min_sketch *c, const void *key, size_t len, uint64_t value) {
    for (uint32_t i = 0; i < c->n; i++) {
        uint32_t col = column_for_row(c, key, len, i);
        c->matrix[i * c->n + col] += value;
    }
}

uint64_t cms_estimate(const count_min_sketch *c, const void *key, size_t len) {
    uint64_t min_count = UINT64_MAX;
    for (uint32_t i = 0; i < c->n; i++) {
        uint32_t col = column_for_row(c, key, len, i);
        uint64_t count = c->matrix[i * c->n + col];
        if (count < min_count) {
            min_count = count;
        }
    }
    return min_count;
}

void cms_reset(count_min_sketch *c) {
    memset(c->matrix, 0, (size_t)c->n * c->m * sizeof(uint64_t));
}

void cms_free(count_min_sketch *c) {
    free(c->matrix);
    c->matrix = NULL;
}
