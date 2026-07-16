#include "../include/sketch/cms.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(void) {
    count_min_sketch cms;
    if (cms_init(&cms, 4, 1024) != 0) {
        return 1;
    }

    const char *alice = "alice";
    const char *bob = "bob";

    for (int i = 0; i < 100; i++)
        cms_add(&cms, alice, strlen(alice), 1);
    for (int i = 0; i < 5; i++)
        cms_add(&cms, bob, strlen(bob), 1);

    uint64_t a = cms_estimate(&cms, alice, strlen(alice));
    uint64_t b = cms_estimate(&cms, bob, strlen(bob));
    uint64_t unknown = cms_estimate(&cms, "carol", 5);

    printf("alice: %llu (expected >= 100)\n", (unsigned long long)a);
    printf("bob: %llu (expected >= 5)\n", (unsigned long long)b);
    printf("carol: %llu (expected 0 or small)\n", (unsigned long long)unknown);

    assert(a >= 100);
    assert(b >= 5);

    printf("All assertions passed.\n");
    cms_free(&cms);
    return 0;
}