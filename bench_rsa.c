#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include "rsa_pss.h"

// Read timestamp counter for cycle measurements
static inline uint64_t rdtsc() {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <iterations>\n", argv[0]);
        return 1;
    }
    
    int iterations = atoi(argv[1]);
    
    rsa_public_key pubkey = {0};
    uint8_t signature[RSA_KEY_BYTES];
    uint8_t out[RSA_KEY_BYTES];
    
    // Initialize dummy modulus (usually should be odd for Montgomery)
    for (int i = 0; i < RSA_KEY_WORDS; i++) {
        pubkey.modulus[i] = 0xFFFFFFFFFFFFFFFFULL - i;
        pubkey.r_squared[i] = i + 1; 
    }
    pubkey.modulus[0] |= 1; // Ensure odd
    pubkey.m0inv = 0x826435; // Dummy m0inv
    
    for (int i = 0; i < RSA_KEY_BYTES; i++) {
        signature[i] = i & 0xFF;
    }
    signature[1] = 0; // ensure smaller than N
    
    // Warmup
    rsa_verify_signature_avx2(&pubkey, signature, out);
    
    // Benchmark AVX2
    uint64_t start_avx2 = rdtsc();
    for (int i = 0; i < iterations; i++) {
        rsa_verify_signature_avx2(&pubkey, signature, out);
    }
    uint64_t end_avx2 = rdtsc();
    
    // Benchmark Scalar
    uint64_t start_scalar = rdtsc();
    for (int i = 0; i < iterations; i++) {
        rsa_verify_signature(&pubkey, signature, out);
    }
    uint64_t end_scalar = rdtsc();
    
    printf("RSA-PSS 3072-bit (e=65537) Verification Benchmark:\n");
    printf("Iterations: %d\n", iterations);
    printf("Scalar Avg Cycles: %llu\n", (unsigned long long)((end_scalar - start_scalar) / iterations));
    printf("AVX2 Avg Cycles: %llu\n", (unsigned long long)((end_avx2 - start_avx2) / iterations));
    
    return 0;
}
