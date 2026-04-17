#include "rsa_pss.h"
#include <string.h>

/**
 * Perform Z = A * B * R^-1 mod N using Word-by-Word Montgomery Multiplication
 * Radix = 2^64
 */
static void mont_mul(uint64_t Z[RSA_KEY_WORDS], const uint64_t A[RSA_KEY_WORDS], const uint64_t B[RSA_KEY_WORDS], const uint64_t N[RSA_KEY_WORDS], uint64_t m0inv) {
    uint64_t T[RSA_KEY_WORDS + 2] = {0};
    
    for (int i = 0; i < RSA_KEY_WORDS; i++) {
        uint64_t m = (T[0] + A[i] * B[0]) * m0inv;
        uint64_t carry_ab = 0;
        uint64_t carry_mn = 0;
        uint64_t carry_add = 0;
        
        for (int j = 0; j < RSA_KEY_WORDS; j++) {
            unsigned __int128 p_ab = (unsigned __int128)A[i] * B[j] + carry_ab;
            unsigned __int128 p_mn = (unsigned __int128)m * N[j] + carry_mn;
            
            uint64_t lo_ab = (uint64_t)p_ab;
            carry_ab = (uint64_t)(p_ab >> 64);
            
            uint64_t lo_mn = (uint64_t)p_mn;
            carry_mn = (uint64_t)(p_mn >> 64);
            
            unsigned __int128 p_sum = (unsigned __int128)T[j] + lo_ab + lo_mn + carry_add;
            T[j] = (uint64_t)p_sum;
            carry_add = (uint64_t)(p_sum >> 64);
        }
        
        // Propagate carries to the top of T
        unsigned __int128 final_sum = (unsigned __int128)T[RSA_KEY_WORDS] + carry_ab + carry_mn + carry_add;
        T[RSA_KEY_WORDS] = (uint64_t)final_sum;
        T[RSA_KEY_WORDS + 1] = (uint64_t)(final_sum >> 64);
        
        // Shift right by 1 word
        for (int j = 0; j < RSA_KEY_WORDS + 1; j++) {
            T[j] = T[j + 1];
        }
        T[RSA_KEY_WORDS + 1] = 0;
    }
    
    // Conditionally subtract N if T >= N
    uint64_t borrow = 0;
    uint64_t sub[RSA_KEY_WORDS];
    for (int i = 0; i < RSA_KEY_WORDS; i++) {
        unsigned __int128 diff = (unsigned __int128)T[i] - N[i] - borrow;
        sub[i] = (uint64_t)diff;
        borrow = (diff >> 64) ? 1 : 0;
    }
    
    // If borrow == 0 or T[RSA_KEY_WORDS] == 1, then T >= N.
    // Actually, T could be up to 2N, so if T[RSA_KEY_WORDS] is 1, it definitely exceeded N.
    int overflow = T[RSA_KEY_WORDS] || !borrow;
    
    for (int i = 0; i < RSA_KEY_WORDS; i++) {
        Z[i] = overflow ? sub[i] : T[i];
    }
}

// Byte reversal for big-endian to little-endian conversion
static void byteswab_copy(uint64_t dst[RSA_KEY_WORDS], const uint8_t src[RSA_KEY_WORDS * 8]) {
    for (int i = 0; i < RSA_KEY_WORDS; i++) {
        uint64_t val = 0;
        for (int j = 0; j < 8; j++) {
            val |= ((uint64_t)src[(RSA_KEY_WORDS - 1 - i) * 8 + j]) << ((7 - j) * 8);
        }
        dst[i] = val;
    }
}

static void byteswab_out(uint8_t dst[RSA_KEY_WORDS * 8], const uint64_t src[RSA_KEY_WORDS]) {
    for (int i = 0; i < RSA_KEY_WORDS; i++) {
        uint64_t val = src[i];
        for (int j = 0; j < 8; j++) {
            dst[(RSA_KEY_WORDS - 1 - i) * 8 + j] = (val >> ((7 - j) * 8)) & 0xFF;
        }
    }
}

bool rsa_verify_signature(const rsa_public_key *pubkey, const uint8_t signature[RSA_KEY_BYTES], uint8_t decrypted_buf[RSA_KEY_BYTES]) {
    uint64_t sig[RSA_KEY_WORDS];
    byteswab_copy(sig, signature);
    
    // Check if signature >= modulus
    uint64_t borrow = 0;
    for (int i = 0; i < RSA_KEY_WORDS; i++) {
        unsigned __int128 diff = (unsigned __int128)sig[i] - pubkey->modulus[i] - borrow;
        borrow = (diff >> 64) ? 1 : 0;
    }
    if (borrow == 0) return false; // sig >= n
    
    // Convert sig to Montgomery form: sig' = sig * R mod n
    // We achieve this by mont_mul(sig, R^2 mod n)
    uint64_t sig_mont[RSA_KEY_WORDS];
    mont_mul(sig_mont, sig, pubkey->r_squared, pubkey->modulus, pubkey->m0inv);
    
    // Exponent e = 65537 (0x10001)
    // Means 16 squarings, 1 multiply
    uint64_t base[RSA_KEY_WORDS];
    memcpy(base, sig_mont, sizeof(base));
    
    for (int i = 0; i < 16; i++) {
        mont_mul(sig_mont, sig_mont, sig_mont, pubkey->modulus, pubkey->m0inv);
    }
    
    // Final multiply
    uint64_t result_mont[RSA_KEY_WORDS];
    mont_mul(result_mont, sig_mont, base, pubkey->modulus, pubkey->m0inv);
    
    // Convert out of Montgomery form: result = result_mont * 1 mod n
    uint64_t one[RSA_KEY_WORDS] = {1};
    uint64_t result[RSA_KEY_WORDS];
    mont_mul(result, result_mont, one, pubkey->modulus, pubkey->m0inv);
    
    byteswab_out(decrypted_buf, result);
    return true;
}
