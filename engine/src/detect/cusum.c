#include "../../include/detect/cusum.h"

void cusum_init(cusum_t *c, double slack, double threshold, double alpha) {
    c->mean = 0;
    c->low = 0;
    c->high = 0;
    c->slack = slack;
    c->threshold = threshold;
    c->alpha = alpha;
    c->warmed_up = 0;
    c->samples = 0;
}

int cusum_update(cusum_t *c, double value) {
    c->samples++;
    if (!c->warmed_up) {
        if (c->samples == 1) {
            c->mean = value;
        } else {
            c->mean = c->alpha * value + (1 - c->alpha) * c->mean;
        }
        if (c->samples >= 5) {
            c->warmed_up = 1;
        }
        return 0;
    }

    double deviation = value - c->mean;
    c->high = c->high + deviation - c->slack;
    if (c->high < 0) {
        c->high = 0;
    }
    c->low = c->low - deviation - c->slack;
    if (c->low < 0) {
        c->low = 0;
    }

    if (c->high > c->threshold) {
        return 1;
    }
    if (c->low > c->threshold) {
        return -1;
    }

    c->mean = c->alpha * value + (1 - c->alpha) * c->mean;
    return 0;
}

void cusum_reset(cusum_t *c) {
    c->low = 0;
    c->high = 0;
}