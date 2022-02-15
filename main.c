#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "./lib/AES.h"



/**
 * @union A union that allow us to deal with our parameters as groups of
 * bytes as well as words. To be used in a future update.
 */
union {
	uint32_t word[4];
	uint8_t byte[16];
} byteWordUnion;

/**
 * @brief A function that parses command line argument strings for
 * hexadecimal numbers. To be updated when AES-196 and AES-256 algorithms are implemented.
 * As for now, and since only AES-128 is impleemented, output is truncated at 16 bytes.
 * @param argv The argv array of arguments.
 * @param argIndex The index of the argument to be parsed.
 * @return A pointer to the parsed argument.
 */
uint8_t *commandLineParser (char **argv, int argIndex)
{
	uint8_t *buffer;
	buffer = (uint8_t*) calloc (16, sizeof (uint8_t));
	for (int i = 0; i < 16; i++) {
		char *temp;
		temp = (uint8_t *) calloc (3, sizeof (char));
		strncpy (temp, argv[argIndex] + 2 * i, 2 * sizeof (char));
		*(buffer + i) = (uint8_t)strtol (temp, NULL, 16);
		free (temp);

	}
	return buffer;
}

int main (int argc, char **argv)
{
	uint8_t *buffer;
	uint8_t *cipherKey;
	if (argc < 3) {
		printf("Usage: %s plaintext key\nBoth plaintext and key should be in hexadecimal format without prefixed 0x.\nBeware!\
		Since only AES-128 is implemented for now, the plaintext and key would be truncated at 16 bytes.",argv[0]);
		exit (1);
	} else {
		buffer = commandLineParser (argv, 1);
		cipherKey = commandLineParser (argv, 2);
	}
	AES128 (buffer, cipherKey);
	for (int i = 0; i < 16; i++) {
		printf ("%.2x", buffer[i]);
	}
	puts("");
	free(buffer);
	free(cipherKey);
	return 0;
}
