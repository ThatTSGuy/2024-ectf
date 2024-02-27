/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */
#include "crypto.h"
#include "wolfssl/wolfcrypt/md5.h"

#include "trng.h"

#include <stdint.h>
#include <string.h>

uint8_t* pad(uint8_t* data, size_t size) {
    int pad_size = size + (16 - size % 16);
    
    uint8_t* ptr = malloc(pad_size);
    memset(ptr, 0, pad_size);

    return ptr;
}

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    Aes ctx; // Context for encryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for encryption
    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_ENCRYPTION);
    if (result != 0)
        return result; // Report error


    // Encrypt each block
    for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
        result = wc_AesEncryptDirect(&ctx, ciphertext + i, plaintext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    Aes ctx; // Context for decryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for decryption
    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_DECRYPTION);
    if (result != 0)
        return result; // Report error

    // Decrypt each block
    for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
        result = wc_AesDecryptDirect(&ctx, plaintext + i, ciphertext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param len The length of the plaintext to encrypt
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    // Pass values to hash
    return wc_Md5Hash((uint8_t *)data, len, hash_out);
}

/** @brief Creates a signature of arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param d_size The size of the data
 * @param secret A pointer to the secret
 * @param s_size The size of the secret
 * @param dest A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int create_sig(uint8_t* data, size_t d_size, uint8_t* secret, size_t s_size, uint8_t* dest)
{
    Md5 md5;
    wc_InitMd5(&md5);

    wc_Md5Update(&md5, data, d_size);
    wc_Md5Update(&md5, secret, s_size);

    wc_Md5Final(&md5, dest);
}

/** @brief Verifies a signature of arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 * @param d_size The size of the data
 * @param secret A pointer to the secret
 * @param s_size The size of the secret
 * @param sig A pointer to the signature of the message
 *
 * @return 0 if the data is authentic, non-zero if the data has been altered
 */
int verify_sig(uint8_t* data, size_t d_size, uint8_t* secret, size_t s_size, uint8_t* sig)
{
    uint8_t self_sig[16];
    create_sig(data, d_size, secret, s_size, self_sig);

    return memcmp(sig, self_sig, 16);
}

/** @brief Creates a true random number
 *
 * @param buffer A pointer to a buffer to store the number
 * @param size The size of the number in bytes
 *
 * @return 0 on success, and non-zero on failure
 */
int trng(uint8_t* buffer, size_t size)
{
    MXC_TRNG_Init();
    MXC_TRNG_Random(buffer, size);
    MXC_TRNG_Shutdown();
}