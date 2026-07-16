#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <stddef.h>

uint64_t fnv1a(const void *data, size_t len, uint64_t seed);

#endif