#ifndef RSA_PSS_H
#define RSA_PSS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Keysize: 3072 bits (384 bytes = 48 uint64_t)
#define RSA_KEY_WORDS 48
#define RSA_KEY_BYTES 384

// Exponent is statically defined for firmware signature verification: 65537
#define RSA_PUB_E 65537

typedef struct {
    uint64_t modulus[RSA_KEY_WORDS]; // n
    uint64_t r_squared[RSA_KEY_WORDS]; // R^2 mod n
    uint64_t m0inv; // -n^{-1} mod 2^64
} rsa_public_key;

/**
 * Perform RSA Montgomery Exponentiation: m = s^e mod n
 * Returns true if successful, false if s >= n (invalid signature)
 * Uses assumed exponent e = 65537.
 */
bool rsa_verify_signature(const rsa_public_key *pubkey, const uint8_t signature[RSA_KEY_BYTES], uint8_t decrypted_buf[RSA_KEY_BYTES]);

/**
 * AVX2 Optimized version
 */
bool rsa_verify_signature_avx2(const rsa_public_key *pubkey, const uint8_t signature[RSA_KEY_BYTES], uint8_t decrypted_buf[RSA_KEY_BYTES]);

#endif // RSA_PSS_H
