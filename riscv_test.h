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
 *   - a pointer to a new cryptor
 * Note:
 *   - the cryptor must be dropped using `drop_cryptor`
 */
const void *new_cryptor(uint8_t (*next_u8)(void));

/**
 * Parameters:
 *   - ptr: a pointer to a cryptor
 *   - data: a pointer to the data to be encrypted
 *   - len: the length of the data
 *   - out_len: a pointer to the length of the encrypted data, 0 if failed
 * Returns:
 *   - a pointer of the encrypted data
 */
const uint8_t *encrypt(const void *ptr, const uint8_t *data, uintptr_t len, uintptr_t *out_len);

/**
 * Parameters:
 *   - ptr: a pointer to a cryptor
 *   - data: a pointer to the data to be decrypted
 *   - len: the length of the data
 *   - out_len: a pointer to the length of the decrypted data, 0 if failed
 * Returns:
 *   - a pointer of the decrypted data
 */
const uint8_t *decrypt(const void *ptr, const uint8_t *data, uintptr_t len, uintptr_t *out_len);

/**
 * Note:
 *   - the cryptor must be dropped using this function
 */
void drop_cryptor(const void *ptr);

#endif  /* riscv_test_h */
