#ifndef HLL_H
#define HLL_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

typedef struct {
    uint32_t prec;
    uint32_t count;
    uint8_t *registers;
} hyperloglog;

int hll_init(hyperloglog *h, uint32_t prec);
void hll_add(hyperloglog *h, const void *key, size_t len);
u_int64_t hll_estimate(const hyperloglog *h);
void hll_reset(hyperloglog *h);
void hll_free(hyperloglog *h);

#endif