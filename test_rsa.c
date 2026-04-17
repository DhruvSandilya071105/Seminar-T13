#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rsa_pss.h"

int main() {
    rsa_public_key pubkey = {0};
    uint8_t signature[RSA_KEY_BYTES];
    uint8_t out_scalar[RSA_KEY_BYTES];
    uint8_t out_avx2[RSA_KEY_BYTES];
    
    // Initialize dummy modulus (usually should be odd for Montgomery)
    for (int i = 0; i < RSA_KEY_WORDS; i++) {
        pubkey.modulus[i] = 0xFFFFFFFFFFFFFFFFULL - i;
        pubkey.r_squared[i] = i + 1; 
    }
    pubkey.modulus[0] |= 1; // Ensure odd
    pubkey.m0inv = 0x826435; // Dummy m0inv
    
    // Dummy signature
    for (int i = 0; i < RSA_KEY_BYTES; i++) {
        signature[i] = i & 0xFF;
    }
    // Ensure signature < modulus
    signature[1] = 0;
    
    printf("Running Scalar Verification...\n");
    bool valid_scalar = rsa_verify_signature(&pubkey, signature, out_scalar);
    
    printf("Running AVX2 Verification...\n");
    bool valid_avx2 = rsa_verify_signature_avx2(&pubkey, signature, out_avx2);
    
    printf("Scalar Result Valid: %d\n", valid_scalar);
    printf("AVX2 Result Valid: %d\n", valid_avx2);
    
    if (valid_scalar == valid_avx2 && memcmp(out_scalar, out_avx2, RSA_KEY_BYTES) == 0) {
        printf("[PASS] AVX2 output matches scalar output exactly.\n");
        return 0;
    } else {
        printf("[FAIL] Outputs differ.\n");
        return 1;
    }
}
