/**
 * @file "simple_crypto.h"
 * @author Ben Janis
 * @brief Simplified Crypto API Header 
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H

#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/hash.h"

/******************************** MACRO DEFINITIONS ********************************/
#define BLOCK_SIZE AES_BLOCK_SIZE
#define KEY_SIZE 16
#define HASH_SIZE MD5_DIGEST_SIZE

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
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext);

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *           ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *           BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *           the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *           plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext);

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *           to be hashed
 * @param len The length of the plaintext to encrypt
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *           hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out);

/** @brief Creates a signature of arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param size The size of the data
 * @param secret A pointer to the 16 byte secret
 * @param dest A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int create_signature(uint8_t* data, size_t size, uint8_t* secret, uint8_t* dest);

/** @brief Verifies a signature of arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 * @param size The size of the data
 * @param secret A pointer to the 16 byte secret
 * @param sig A pointer to the signature of the message
 *
 * @return 0 if the data is authentic, -1 if the data has been altered
 */
int verify_signature(uint8_t* data, size_t size, uint8_t* secret, uint8_t* sig);

/** @brief Creates a true random number
 *
 * @param buffer A pointer to a buffer to store the number
 * @param size The size of the number in bytes
 *
 * @return 0 on success, and non-zero on failure
 */
int trng(uint8_t* buffer, size_t size);

#endif