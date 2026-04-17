#ifndef SHA384_H
#define SHA384_H

#include <stdint.h>
#include <stddef.h>

#define SHA384_DIGEST_SIZE 48
#define SHA384_BLOCK_SIZE 128

typedef struct {
    uint64_t h[8];
    uint8_t buffer[SHA384_BLOCK_SIZE];
    size_t length;
    uint64_t totalLength;
} sha384_context;

void sha384_init(sha384_context *ctx);
void sha384_update(sha384_context *ctx, const uint8_t *data, size_t len);
void sha384_final(sha384_context *ctx, uint8_t digest[SHA384_DIGEST_SIZE]);

#endif // SHA384_H
