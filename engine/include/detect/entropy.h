#ifndef ENTROPY_H
#define ENTROPY_H

#include <stdint.h>
#include <stddef.h>

double entropy(const uint64_t *counts, size_t n);

#endif