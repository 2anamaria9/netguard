#include "../include/hash.h"
#include <stdint.h>

#define PRIME 0x100000001b3ULL
#define OFFSET 0xcbf29ce484222325ULL

uint64_t fnv1a(const void *data, size_t len, uint64_t seed) {
    const unsigned char *bytes = (const unsigned char*)data;
    uint64_t hash = OFFSET ^ seed;

    for (size_t i = 0; i < len; i++) {
        hash = hash ^ bytes[i];
        hash = hash * PRIME;
    }
    return hash;
}

