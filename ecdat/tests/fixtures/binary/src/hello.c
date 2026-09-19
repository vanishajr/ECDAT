/* Phase 6 control fixture: no cryptography at all. Must yield zero
 * crypto findings while still exercising the cheap pass. */
#include <stdio.h>

int main(void) {
    printf("hello, deterministic world\n");
    return 0;
}
