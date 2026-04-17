#include "sha384.h"
#include <string.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define EP1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define SIG0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ ((x) >> 7))
#define SIG1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ ((x) >> 6))

static const uint64_t K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static inline uint64_t byteswap64(uint64_t val) {
    return ((val & 0xFF00000000000000ULL) >> 56) |
           ((val & 0x00FF000000000000ULL) >> 40) |
           ((val & 0x0000FF0000000000ULL) >> 24) |
           ((val & 0x000000FF00000000ULL) >> 8)  |
           ((val & 0x00000000FF000000ULL) << 8)  |
           ((val & 0x0000000000FF0000ULL) << 24) |
           ((val & 0x000000000000FF00ULL) << 40) |
           ((val & 0x00000000000000FFULL) << 56);
}

void UpdateSHA512(uint64_t digest[8], const uint8_t *dataBlock, int datalen, const void *ignored) {
    (void)ignored;
    uint64_t W[80];
    
    for (int block = 0; block < datalen / SHA384_BLOCK_SIZE; block++) {
        const uint8_t *p = dataBlock + block * SHA384_BLOCK_SIZE;
        
        for (int i = 0; i < 16; i++) {
            uint64_t val;
            memcpy(&val, p + i * 8, 8);
            W[i] = byteswap64(val);
        }
        
        for (int i = 16; i < 80; i++) {
            W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
        }
        
        uint64_t a = digest[0];
        uint64_t b = digest[1];
        uint64_t c = digest[2];
        uint64_t d = digest[3];
        uint64_t e = digest[4];
        uint64_t f = digest[5];
        uint64_t g = digest[6];
        uint64_t h = digest[7];
        
        for (int i = 0; i < 80; i++) {
            uint64_t temp1 = h + EP1(e) + CH(e, f, g) + K[i] + W[i];
            uint64_t temp2 = EP0(a) + MAJ(a, b, c);
            
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        
        digest[0] += a;
        digest[1] += b;
        digest[2] += c;
        digest[3] += d;
        digest[4] += e;
        digest[5] += f;
        digest[6] += g;
        digest[7] += h;
    }
}

void sha384_init(sha384_context *ctx) {
    ctx->length = 0;
    ctx->totalLength = 0;
    ctx->h[0] = 0xcbbb9d5dc1059ed8ULL;
    ctx->h[1] = 0x629a292a367cd507ULL;
    ctx->h[2] = 0x9159015a3070dd17ULL;
    ctx->h[3] = 0x152fecd8f70e5939ULL;
    ctx->h[4] = 0x67332667ffc00b31ULL;
    ctx->h[5] = 0x8eb44a8768581511ULL;
    ctx->h[6] = 0xdb0c2e0d64f98fa7ULL;
    ctx->h[7] = 0x47b5481dbefa4fa4ULL;
}

void sha384_update(sha384_context *ctx, const uint8_t *data, size_t len) {
    ctx->totalLength += len;
    
    if (ctx->length > 0) {
        size_t available = SHA384_BLOCK_SIZE - ctx->length;
        if (len >= available) {
            memcpy(ctx->buffer + ctx->length, data, available);
            UpdateSHA512(ctx->h, ctx->buffer, SHA384_BLOCK_SIZE, NULL);
            data += available;
            len -= available;
            ctx->length = 0;
        } else {
            memcpy(ctx->buffer + ctx->length, data, len);
            ctx->length += len;
            return;
        }
    }
    
    if (len >= SHA384_BLOCK_SIZE) {
        size_t blocks = len / SHA384_BLOCK_SIZE;
        size_t process_len = blocks * SHA384_BLOCK_SIZE;
        UpdateSHA512(ctx->h, data, process_len, NULL);
        data += process_len;
        len -= process_len;
    }
    
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->length = len;
    }
}

void sha384_final(sha384_context *ctx, uint8_t digest[SHA384_DIGEST_SIZE]) {
    uint8_t padding[SHA384_BLOCK_SIZE * 2] = {0};
    padding[0] = 0x80;
    
    size_t pad_len = SHA384_BLOCK_SIZE - ((ctx->length + 16) % SHA384_BLOCK_SIZE);
    if (pad_len < 16) pad_len += SHA384_BLOCK_SIZE;
    
    uint64_t bits = ctx->totalLength * 8;
    
    padding[pad_len + 8] = (bits >> 56) & 0xFF;
    padding[pad_len + 9] = (bits >> 48) & 0xFF;
    padding[pad_len + 10] = (bits >> 40) & 0xFF;
    padding[pad_len + 11] = (bits >> 32) & 0xFF;
    padding[pad_len + 12] = (bits >> 24) & 0xFF;
    padding[pad_len + 13] = (bits >> 16) & 0xFF;
    padding[pad_len + 14] = (bits >> 8) & 0xFF;
    padding[pad_len + 15] = (bits) & 0xFF;
    
    sha384_update(ctx, padding, pad_len + 16);
    
    for (int i = 0; i < 6; i++) {
        uint64_t h_swapped = byteswap64(ctx->h[i]);
        memcpy(digest + (i * 8), &h_swapped, 8);
    }
}
