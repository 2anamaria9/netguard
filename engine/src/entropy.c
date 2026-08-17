#include "../include/entropy.h"
#include <math.h>
#include <stdint.h>

double entropy(const uint64_t *counts, size_t n) {
    uint64_t sum = 0;
    for (size_t i = 0; i < n; i++) {
        sum = sum + counts[i];
    }
    if (sum == 0) {
        return 0;
    }

    double ent = 0;
    for (size_t i = 0; i < n; i++) {
        if (counts[i] == 0) {
            continue;
        }
        double p = (double)counts[i] / (double)sum;
        ent = ent - p * log2(p);
    }
    return ent;
}