#include "../include/entropy.h"
#include <stdio.h>

int main(void) {
    uint64_t concentrated[] = {1000, 0, 0, 0};
    printf("Concentrated (should be ~0): %.3f\n", entropy(concentrated, 4));

    uint64_t uniform[] = {250, 250, 250, 250};
    printf("Uniform 4-way (should be 2.0): %.3f\n", entropy(uniform, 4));

    uint64_t normal[] = {900, 50, 30, 20};
    printf("Normal-ish (should be low): %.3f\n", entropy(normal, 4));
    
    uint64_t uniform8[] = {125, 125, 125, 125, 125, 125, 125, 125};
    printf("Uniform 8-way (should be 3.0): %.3f\n", entropy(uniform8, 8));

    return 0;
}