#include "../include/cusum.h"
#include <stdio.h>

int main(void) {
    cusum_t c;
    cusum_init(&c, 0.5, 3.0, 0.3);

    printf("Warming up + normal traffic:\n");
    double normal[] = {4.0, 4.1, 3.9, 4.0, 4.2, 3.8, 4.1, 4.0};
    for (int i = 0; i < 8; i++) {
        int r = cusum_update(&c, normal[i]);
        printf("  value=%.1f -> %s\n", normal[i],
               r == 0 ? "ok" : (r == 1 ? "UP ALARM" : "DOWN ALARM"));
    }

    printf("Scan starts (entropy jumps):\n");
    double scan[] = {7.0, 7.2, 7.1, 7.3, 7.0};
    for (int i = 0; i < 5; i++) {
        int r = cusum_update(&c, scan[i]);
        printf("  value=%.1f -> %s\n", scan[i],
               r == 0 ? "ok" : (r == 1 ? "UP ALARM" : "DOWN ALARM"));
    }

    return 0;
}