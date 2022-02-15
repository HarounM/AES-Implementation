#include<stdint.h>


/** @file This file contains the definitions of functions used to
 * implement the AES encryption algorithm. All these functions are to be
 * updated to support the usage of AES-196 and AES-256. As for now, only AES-128 is supported
 */


/**
 * @brief A function that applies the subBytes transformation on
 * a single byte. This is implemented as a simple substitution using
 * the lookup table. This is to avoid wasting resources on performing
 * the algorithm each time.
 * @param byte The input byte.
 * @return The result of the subBytes transformation.
 */
uint8_t subByte (uint8_t byte);

/**
 * @brief A function that applies the subBytes transformation on the
 * State array. It uses the aforementioned subByte function.
 * @param StateArray A pointer to the State array.
 */
void SubBytes (uint8_t *StateArray);

/**
 * @brief A function that applies the ShiftRows transformation on the
 * State array.
 * @param StateArray A pointer to the State array.
 */
void ShiftRows (uint8_t *StateArray);

/**
 * @brief A function that multiplies a byte by 2 over the GF(2^8).
 * @param byte The byte to be multiplied by 2.
 * @return The multiplication of that byte by 2 over GF(2^8)
 */
uint8_t GMul2 (uint8_t byte);

/**
 * @brief A function that applies the MixCols transformation on the
 * State array.
 * @param StateArray A pointer to the State array.
 */
void MixCols (uint8_t *StateArray);

/**
 * @brief A function that performs the key expansion algorithm on the
 * cipher key. To be updated when AES-196 and AES-256 algorithms are
 * implemented.
 * @param cipherKey A pointer to the cipher key to be expanded.
 * @return A pointer to the expanded key.
 */
uint8_t *KeyExpansion (uint8_t *cipherKey);

/**
 * @brief A functions that applies the AddRoundKey transformation on
 * the State array.
 * @param StateArray A pointer to the State array.
 * @param RoundKey A pointer to the round key.
 */
void AddRoundKey (uint8_t *StateArray, const  uint8_t *RoundKey);

/**
 * @brief A function that encrypts a plaintext using the AES-128 algorithm.
 * @param plaintext A pointer to the plaintext.
 * @param cipherKey A pointer to the cipher key.
 */
void AES128 (uint8_t *plaintext, uint8_t *cipherKey);

/**
 * @brief A function that encrypts a plaintext using the AES-196 algorithm.
 * To be implemented.
 * @param plaintext A pointer to the plaintext.
 * @param cipherKey A pointer to the cipher key.
 */
void AES196 (uint8_t *plaintext, uint8_t *cipherKey);

/**
 * @brief A function that encrypts a plaintext using the AES-256 algorithm.
 * To be implemented.
 * @param plaintext A pointer to the plaintext.
 * @param cipherKey A pointer to the cipher key.
 */
void AES256 (uint8_t *plaintext, uint8_t *cipherKey);