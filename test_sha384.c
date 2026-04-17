#include <stdio.h>
#include <string.h>
#include "sha384.h"

int main() {
    sha384_context ctx;
    uint8_t digest[SHA384_DIGEST_SIZE];
    
    // NIST Test Vector for "abc"
    const char *test1 = "abc";
    sha384_init(&ctx);
    sha384_update(&ctx, (const uint8_t*)test1, strlen(test1));
    sha384_final(&ctx, digest);
    
    printf("SHA384(\"abc\") = ");
    for(int i = 0; i < SHA384_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    // Expected: cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
    
    return 0;
}
