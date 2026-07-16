#ifndef CMS_H
#define CMS_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t n;
    uint32_t m;
    uint64_t *matrix;
} count_min_sketch;

int cms_init(count_min_sketch *c, uint32_t n, uint32_t m);
void cms_add(count_min_sketch *c, const void *key, size_t len, uint64_t value);
uint64_t cms_estimate(const count_min_sketch *c, const void *key, size_t len);
void cms_reset(count_min_sketch *c);
void cms_free(count_min_sketch *c);

#endif