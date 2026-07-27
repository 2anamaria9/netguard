#include "../include/sketch/hll.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    hyperloglog hll;
    if (hll_init(&hll, 12) != 0) {   // 4096 registers
        fprintf(stderr, "init failed\n");
        return 1;
    }

    int true_count = 10000;
    for (int i = 0; i < true_count; i++)
        hll_add(&hll, &i, sizeof(i));

    for (int i = 0; i < true_count; i++)
        hll_add(&hll, &i, sizeof(i));

    uint64_t est = hll_estimate(&hll);
    double error = 100.0 * (double)(est > (uint64_t)true_count ?
                   est - true_count : true_count - est) / true_count;

    printf("True distinct: %d\n", true_count);
    printf("HLL estimate: %llu\n", (unsigned long long)est);
    printf("Error: %.2f%%\n", error);

    if (error < 5.0)
        printf("PASS (within 5%%)\n");
    else
        printf("FAIL (error too high)\n");

    hll_free(&hll);
    return 0;
}