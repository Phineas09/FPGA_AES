#include <stdint.h>
#include <stddef.h>

#define Nb 4  // Number of columns (32-bit words) comprising the State - state[4][4]
#define Nk 4  // Number of 32-bit words comprising the Cipher Key
#define Nr 10 // Number of rounds, which is a function of Nk and Nb

typedef uint8_t uchar;

void printHex(uint8_t *str);

/**
 * @brief Encrypt and decrypt function of AES ECB
 * 
 * @param aesKey aes key as array of 16 bytes
 * @param input input must be of size 16
 * @param output must be an allocated array of 16 bytes
 * @param mode encrypt or decrypt (0 for encryption and anything else for decryption)
 */
void AES_ECB(uint8_t *aesKey, uint8_t *input, uint8_t *output, int mode);