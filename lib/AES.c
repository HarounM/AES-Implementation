#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "AES.h"

uint8_t subByte (uint8_t byte)
{
	const uint8_t sbox[256] = {
//		0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  //F
	}; 
	return sbox[byte];
}
void SubBytes (uint8_t *StateArray)
{
	for (int i = 0; i < 16; i++) {
		*(StateArray + i) = subByte (*(StateArray + i));
	}

}
void ShiftRows (uint8_t *StateArray)
{
	uint8_t temp, temp1;
	temp = StateArray[1];
	StateArray[1] = StateArray[5];
	StateArray[5] = StateArray[9];
	StateArray[9] = StateArray[13];
	StateArray[13] = temp;

	temp = StateArray[2];
	temp1 = StateArray[6];
	StateArray[2] = StateArray[10];
	StateArray[6] = StateArray[14];
	StateArray[10] = temp;
	StateArray[14] = temp1;

	temp = StateArray[15];
	StateArray[15] = StateArray[11];
	StateArray[11] = StateArray[7];
	StateArray[7] = StateArray[3];
	StateArray[3] = temp;
}
uint8_t GMul2 (uint8_t byte)
{
	uint8_t result;
	/*  A multiplication by 2 could be implemented as a left shift on the
	 *  binary level. And since our result is stored on exactly 8 bits,
	 *  the last bit would be discarded after the shift.
	 *
	 *  0x11b is the hexadecimal representation of Rijndael's GF(2^8)
	 *  reduction polynomial. And since our result is stored on exactly
	 *  8 bits, and since the last bit was already discarded during the
	 *  left shift, we could use 0x1b as a reducing polynomial.
	 *
	 *  Remark : To be more straightforward, if there weren't a
	 *  limitation to our variable's size, a shift left would've turned
	 *  it into a 9 bit number (if the 8th bit was 1), and then the
	 *  leftmost 1 in 0x11b would've turned the 9th bit into 0, thus
	 *  turning our number into an 8bit number again. That's why using
	 *  0x1b as the reducing polynomial is enough, because if the 8th bit
	 *  was 0, then it already doesn't matter, and if it was 1, then the
	 *  size limitation would've discarded it, replacing the xor with the
	 *  leftmost 1 in 0x11b.
	 */
	if (byte > 0x80) {
		result = (byte << 1) ^ 0x1b;
	} else {
		result = byte << 1;
	}
	return result;
}
void MixCols (uint8_t *StateArray)
{
	for (int i = 0; i < 16; i += 4) {
		uint8_t temp = StateArray[i], temp1 = StateArray[i + 1], temp2 = StateArray[i + 2], temp3 = StateArray[i + 3];
		StateArray[i] = GMul2 (temp) ^ GMul2 (temp1) ^ temp1 ^ temp2 ^ temp3;
		StateArray[i + 1] = temp ^ GMul2 (temp1) ^ GMul2 (temp2) ^ temp2 ^ temp3;
		StateArray[i + 2] = temp ^ temp1 ^ GMul2 (temp2) ^ GMul2 (temp3) ^ temp3;
		StateArray[i + 3] = GMul2 (temp) ^ temp ^ temp1 ^ temp2 ^ GMul2 (temp3);
	}
}
void AddRoundKey (uint8_t *StateArray, const uint8_t *RoundKey)
{
	for (int i = 0; i < 16; i++) {
		StateArray[i] = StateArray[i] ^ RoundKey[i];
	}
}
uint8_t *KeyExpansion (uint8_t *cipherKey)
{
	uint8_t *expandedKey;
	expandedKey = (uint8_t*) calloc(176, sizeof(uint8_t));
	memcpy (expandedKey, cipherKey, 16 * sizeof (uint8_t));
	const uint8_t rcon[10] = {0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
	for (int i = 16; i < 176; i += 4) {
		if (i % 16 == 0) {
			expandedKey[i] = expandedKey[i - 16] ^ subByte (expandedKey[i - 3]) ^ rcon[(i / 16) - 1];
			expandedKey[i + 1] = expandedKey[i - 15] ^ subByte (expandedKey[i - 2]);
			expandedKey[i + 2] = expandedKey[i - 14] ^ subByte (expandedKey[i - 1]);
			expandedKey[i + 3] = expandedKey[i - 13] ^ subByte (expandedKey[i - 4]);
		} else {
			expandedKey[i] = expandedKey[i - 16] ^ expandedKey[i - 4];
			expandedKey[i + 1] = expandedKey[i - 15] ^ expandedKey[i - 3];
			expandedKey[i + 2] = expandedKey[i - 14] ^ expandedKey[i - 2];
			expandedKey[i + 3] = expandedKey[i - 13] ^ expandedKey[i - 1];
		}
	}
	return expandedKey;
}
void AES128 (uint8_t *plaintext, uint8_t *cipherKey)
{
	uint8_t *expandedKey;
	uint8_t roundKey[16];
	expandedKey = KeyExpansion (cipherKey);

	// First Round
	memcpy (roundKey, expandedKey, 16 * sizeof (uint8_t));
	AddRoundKey (plaintext, roundKey);
	SubBytes (plaintext);
	ShiftRows (plaintext);
	MixCols (plaintext);
	memcpy (roundKey, (expandedKey + 16), 16 * sizeof (uint8_t));
	AddRoundKey (plaintext, roundKey);
	// The next 8 rounds
	for (int i = 2; i < 10; i++) {
		SubBytes (plaintext);
		ShiftRows (plaintext);
		MixCols (plaintext);
		memcpy (roundKey, (expandedKey + (16 * i)), 16 * sizeof (uint8_t));
		AddRoundKey (plaintext, roundKey);
	}
	// Last Round
	SubBytes (plaintext);
	ShiftRows (plaintext);
	memcpy (roundKey, (expandedKey + 160), 16 * sizeof (uint8_t));
	AddRoundKey (plaintext, roundKey);
	free(expandedKey);
}
