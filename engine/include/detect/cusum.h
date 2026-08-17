#ifndef CUSUM_H
#define CUSUM_H

#include <stdint.h>
#include <threads.h>

typedef struct{
    double mean;
    double low;
    double high;
    double slack;
    double threshold;
    double alpha;
    int warmed_up;
    int samples;
} cusum_t;

void cusum_init(cusum_t *c, double slack, double threshold, double alpha);
int cusum_update(cusum_t *c, double value);
void cusum_reset(cusum_t *c);

#endif