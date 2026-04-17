#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include "sha384.h"

// Read timestamp counter for cycle measurements
static inline uint64_t rdtsc() {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <buffer_size_mb>\n", argv[0]);
        return 1;
    }
    
    int mb = atoi(argv[1]);
    size_t size = mb * 1024 * 1024;
    uint8_t *buffer = (uint8_t*)malloc(size);
    if (!buffer) return 1;
    
    // Fill with dummy data
    for (size_t i = 0; i < size; i++) buffer[i] = (uint8_t)(i & 0xFF);
    
    sha384_context ctx;
    uint8_t digest[SHA384_DIGEST_SIZE];
    
    // Warmup
    sha384_init(&ctx);
    sha384_update(&ctx, buffer, 4096);
    sha384_final(&ctx, digest);
    
    // Benchmark
    uint64_t start = rdtsc();
    
    sha384_init(&ctx);
    sha384_update(&ctx, buffer, size);
    sha384_final(&ctx, digest);
    
    uint64_t end = rdtsc();
    
    double cycles_per_byte = (double)(end - start) / size;
    
    printf("SHA-384 Benchmark:\n");
    printf("Buffer Size: %d MB\n", mb);
    printf("Total Cycles: %llu\n", (unsigned long long)(end - start));
    printf("Cycles per Byte: %.2f\n", cycles_per_byte);
    
    free(buffer);
    return 0;
}
