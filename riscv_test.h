#ifndef riscv_test_h
#define riscv_test_h

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Parameters:
 *   - next_u8: a function pointer to a function that returns a random u8
 * Returns:
 *   - a pointer to a new signature
 * Note:
 *   - the signature must be dropped using `drop_signature`
 */
const void *new_signature(uint8_t (*next_u8)(void));

/**
 * Parameters:
 *   - ptr: a pointer to a cryptor
 *   - data: message to be signed
 *   - out: a pointer to the length of the encrypted data, 0 if failed
 * Returns:
 *   - the signature data
 */
void sign(const void *ptr, const uint8_t (*data)[32], uint8_t (*out)[64]);

/**
 * Parameters:
 *   - ptr: a pointer to a cryptor
 *   - data: message to be verified
 *   - signature_bytes: signature to be verified
 * Returns:
 *   - true if the signature is valid, false otherwise
 */
bool verify(const void *ptr, const uint8_t (*data)[32], const uint8_t (*signature_bytes)[64]);

/**
 * Note:
 *   - the signature must be dropped using this function
 */
void drop_signature(const void *ptr);

#endif  /* riscv_test_h */
