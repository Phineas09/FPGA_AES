#include "aes.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Official Doc https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901427
// Static lookup tables needed for substitution and key generation

// Aes-128

void printHex(uint8_t *str)
{
    uint8_t len = 16;
    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x ", str[i]);
    printf("\n");
}

// https://en.wikipedia.org/wiki/Rijndael_S-box
static const uchar sbox[] = { // 16x16
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const uchar rsbox[] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

static const uchar rcon[] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// Key Expansion Function, this is used to get generate RoundKeys for all rounds
// Based on rcon and the initial key
static void KeyExpansion(uchar *aesKey, volatile uchar *RoundKey)
{
    int i, j, k, u, l, x;

    uchar varTemp = 0;
    uchar rotTmp = 0;
    volatile uchar temp[4];
#pragma HLS ARRAY_PARTITION variable = temp dim = 0 complete

    // First round key is actually the key (128 bits / 16 bytes)
KeyExpansionLoop1:
    for (l = 0; l < Nk * 4; l++)
        RoundKey[l] = aesKey[l];

KeyExpansionLoop2:
    for (i = Nk; i < Nb * (Nr + 1); i++)
    {
#pragma HLS pipeline off
        // #pragma HLS loop_flatten off
        k = (i - 1) << 2;
        // memcpy(temp, RoundKey + k, 4);
    KeyExpansionLoop3:
        for (x = 0; x < 3; x += 2)
        {
            temp[x] = RoundKey[k + x];
            temp[x + 1] = RoundKey[k + x + 1];
        }

        if (i % Nk == 0)
        {
            // RotWord() to the left
            {
                rotTmp = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = rotTmp;
            }

            // Subword()
            {

                varTemp = temp[3];
                temp[0] = sbox[temp[0]];
                temp[1] = sbox[temp[1]];
                temp[2] = sbox[temp[2]];
                temp[3] = sbox[varTemp];
            }

            // Xor With Rcon, but only the first byte as per page 31
            temp[0] = temp[0] ^ rcon[i / Nk];
        }
        else if (Nk > 6 && i % Nk == 4)
        { // This is for AES256, the only one with NK = 8

            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }

        j = i * 4;        // Current key word
        u = (i - Nk) * 4; // Last generated key word (4 bytes as this standard)

    KeyExpansionLoop4:
        for (x = 0; x < 4; x++)
        {
#pragma HLS loop_flatten off
            RoundKey[j + x] = RoundKey[u + x] ^ temp[x];
        }

        //        RoundKey[j + 0] = RoundKey[u + 0] ^ temp[0];
        //        RoundKey[j + 1] = RoundKey[u + 1] ^ temp[1];
        //        RoundKey[j + 2] = RoundKey[u + 2] ^ temp[2];
        //        RoundKey[j + 3] = RoundKey[u + 3] ^ temp[3];
    }
}

// Helper Function Gallois Field Multiplication

static uchar GFMul(uchar a, uchar b)
{
    uchar result = 0;
    uchar shiftGreaterThan255 = 0;
    uchar i = 0;
    // Loop through each bit in `b`
    for (i = 0; i < 8; i++)
    {
        // If the LSB is set (i.e. we're not multiplying out by zero for this polynomial term)
        // then we xor the result with `a` (i.e. adding the polynomial terms of a)
        if (b & 1)
        {
            result ^= a;
        }

        // Double `a`, keeping track of whether that causes `a` to "leave" the field.
        shiftGreaterThan255 = a & 0x80;
        a <<= 1;

        // The next bit we look at in `b` will represent multiplying the terms in `a`
        // by the next power of 2, which is why we can achieve the same result by shifting `a` left.
        // If `a` left the field, we need to modulo with irreducible polynomial term.
        if (shiftGreaterThan255)
        {
            // Note that we use 0x1b instead of 0x11b. If we weren't taking advantage of
            // u8 overflow (i.e. by using u16, we would use the "real" term)
            a ^= 0x1b;
        }

        // Shift `b` down in order to look at the next LSB (worth twice as much in the multiplication)
        b >>= 1;
    }

    return result;
}

// Now we will implement each function in this Cipher
// 1.SubBytes()
// 2.ShiftRows()
// 3.MixColumns()
// 4.AddKeyRound()

// Use the lookup table sbox, the new value of the state will be detebmined
// by the intersection of the row state[j][i](0) with column index state[j][i](1)
// given that state[1][1] = {53} state'[1][1] will be sbox[53] = {ed}
// we have state of [j][i] to conform the documentation nubering, same thing otherwise ([i][j])

// 1.SubBytes()
static void SubBytes(volatile uchar state[4][4])
{
    uchar i, j;
SubBytesLoop1:
    for (i = 0; i < 4; i++)
    SubBytesLoop2:
        for (j = 0; j < 4; j++)
            state[j][i] = sbox[state[j][i]];
}

// 1'.InvSubBytes()
static void InvSubBytes(volatile uchar state[4][4])
{
    uchar i, j;
InvSubBytesLoop1:
    for (i = 0; i < 4; i++)
    InvSubBytesLoop2:
        for (j = 0; j < 4; j++)
            state[j][i] = rsbox[state[j][i]];
}

// 2.ShiftRows()
static void ShiftRows(volatile uchar state[4][4])
{
    // Manually rotate the second, third and fourth rows by 1, 2 and 3 position to the left

    uchar temp = 0;

    // Rotate second row with one position to the left

    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Rotate third row with two positions to the left

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;

    temp = state[2][3];
    state[2][3] = state[2][1];
    state[2][1] = temp;

    // Rotate forth row with three positions to the left (aka 1 rotation to right)

    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

// 2'.InvShiftRows()
static void InvShiftRows(volatile uchar state[4][4])
{
    // Manually rotate the second, third and fourth rows by 1, 2 and 3 position to the left

    uchar temp = 0;

    // Rotate second row with one position to the right

    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // temp = state[1][0];
    // state[1][0] = state[1][1];
    // state[1][1] = state[1][2];
    // state[1][2] = state[1][3];
    // state[1][3] = temp;

    // Rotate third row with two positions to the left

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;

    temp = state[2][3];
    state[2][3] = state[2][1];
    state[2][1] = temp;

    // Rotate forth row with three positions to the right (aka 1 rotation to left)

    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

// https://snipplr.com/view/67929/aes-one-round-decrypt
// https://github.com/francisrstokes/githublog/blob/main/2022/6/15/rolling-your-own-crypto-aes.md

// 3.MixColumns()
static void MixColumns(volatile uchar state[4][4])
{
    uchar temp[] = {0, 0, 0, 0};
    uchar stateTemp[4];

    uchar i, j;

    // Do the multiplication in the temp vector, then move them to the state matrix

MixColumnLoop3:
    for (i = 0; i < 4; i++)
    {

        stateTemp[0] = state[0][i];
        stateTemp[1] = state[1][i];
        stateTemp[2] = state[2][i];
        stateTemp[3] = state[3][i];

        //         temp[0] = GFMul(0x02, state[0][i]) ^ GFMul(0x03, state[1][i]) ^ state[2][i] ^ state[3][i];
        //         temp[1] = state[0][i] ^ GFMul(0x02, state[1][i]) ^ GFMul(0x03, state[2][i]) ^ state[3][i];
        //         temp[2] = state[0][i] ^ state[1][i] ^ GFMul(0x02, state[2][i]) ^ GFMul(0x03, state[3][i]);
        //         temp[3] = GFMul(0x03, state[0][i]) ^ state[1][i] ^ state[2][i] ^ GFMul(0x02, state[3][i]);

        temp[0] = GFMul(0x02, stateTemp[0]) ^ GFMul(0x03, stateTemp[1]) ^ stateTemp[2] ^ stateTemp[3];
        temp[1] = stateTemp[0] ^ GFMul(0x02, stateTemp[1]) ^ GFMul(0x03, stateTemp[2]) ^ stateTemp[3];
        temp[2] = stateTemp[0] ^ stateTemp[1] ^ GFMul(0x02, stateTemp[2]) ^ GFMul(0x03, stateTemp[3]);
        temp[3] = GFMul(0x03, stateTemp[0]) ^ stateTemp[1] ^ stateTemp[2] ^ GFMul(0x02, stateTemp[3]);

    MixColumnLoop4:
        for (size_t j = 0; j < 4; j++)
            state[j][i] = temp[j];
    }
}

// 3'.InvMixColumns()
static void InvMixColumns(volatile uchar state[4][4])
{
    uchar temp[] = {0, 0, 0, 0};
    uchar stateTemp[4];

    uchar i, j;

InvMixColumnLoop1:
    for (i = 0; i < 4; i++)
    {

        stateTemp[0] = state[0][i];
        stateTemp[1] = state[1][i];
        stateTemp[2] = state[2][i];
        stateTemp[3] = state[3][i];

        temp[0] = GFMul(0x0e, stateTemp[0]) ^ GFMul(0x0b, stateTemp[1]) ^ GFMul(0x0d, stateTemp[2]) ^ GFMul(0x09, stateTemp[3]);
        temp[1] = GFMul(0x0e, stateTemp[1]) ^ GFMul(0x0b, stateTemp[2]) ^ GFMul(0x0d, stateTemp[3]) ^ GFMul(0x09, stateTemp[0]);
        temp[2] = GFMul(0x0e, stateTemp[2]) ^ GFMul(0x0b, stateTemp[3]) ^ GFMul(0x0d, stateTemp[0]) ^ GFMul(0x09, stateTemp[1]);
        temp[3] = GFMul(0x0e, stateTemp[3]) ^ GFMul(0x0b, stateTemp[0]) ^ GFMul(0x0d, stateTemp[1]) ^ GFMul(0x09, stateTemp[2]);

    InvMixColumnLoop2:
        for (size_t j = 0; j < 4; j++)
            state[j][i] = temp[j];
    }
}

// 4.AddKeyRound() same as it is only a XOR
static void AddKeyRound(uchar round, volatile uchar state[4][4], const uchar *RoundKey)
{
    uchar i, j;
AddKeyRoundLoop1:
    for (i = 0; i < 4; i++)
    {
    AddKeyRoundLoop2:
        for (j = 0; j < 4; j++)
            state[j][i] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
}

// Cipher is the main function that encrypts the PlainText.
static void Cipher(volatile uchar state[4][4], uchar *RoundKey)
{

    uint8_t round = 0;
    AddKeyRound(0, state, RoundKey);
CipherLoop1:
    for (round = 1;; round++)
    {
// Prevent Cipher loop from being flattened
#pragma HLS loop_flatten off
        SubBytes(state);
        ShiftRows(state);
        if (round == Nr)
            break;
        MixColumns(state);
        AddKeyRound(round, state, RoundKey);
    }

    AddKeyRound(Nr, state, RoundKey);
}

static void InvCipher(volatile uchar state[4][4], uchar *RoundKey)
{
    uint8_t round = 0;

    AddKeyRound(Nr, state, RoundKey);

InvCipherLoop1:
    for (round = (Nr - 1);; round--)
    {
#pragma HLS loop_flatten off
        InvShiftRows(state);
        InvSubBytes(state);
        AddKeyRound(round, state, RoundKey);
        if (round == 0)
            break;
        InvMixColumns(state);
    }
}

/**
 * @brief Encrypt and decrypt function of AES ECB
 *
 * @param aesKey aes key as array of 16 bytes
 * @param input input must be of size 16
 * @param output must be an allocated array of 16 bytes
 * @param mode encrypt or decrypt (0 for encryption and anything else for decryption)
 */
void AES_ECB(uint8_t *aesKey, uint8_t *input, uint8_t *output, int mode)
{
#pragma HLS ARRAY_PARTITION variable = sbox dim = 0 complete
#pragma HLS ARRAY_PARTITION variable = rsbox dim = 0 complete

    volatile uchar RoundKey[(Nr + 1) * Nb * 4]; // Rounds + Key(1) * 16
#pragma HLS ARRAY_PARTITION variable = RoundKey dim = 0 complete
    KeyExpansion(aesKey, RoundKey);
    volatile uchar statePrt[4][4];
#pragma HLS ARRAY_PARTITION variable = statePrt dim = 0 complete

    uchar i = 0;
    uchar j = 0;
    // As per Cipher Example Appendix B

AES_ECB_Loop1:
    for (i = 0; i < 4; i++)
    AES_ECB_Loop2:
        for (j = 0; j < 4; j++)
            statePrt[j][i] = input[j + (i * 4)];

    if (mode == 0)
        Cipher(statePrt, (uchar *)(&RoundKey));
    else
        InvCipher(statePrt, (uchar *)(&RoundKey));
    // printHex(statePrt);
    // Copy the result back to out

AES_ECB_Loop3:
    for (i = 0; i < 4; i++)
    AES_ECB_Loop4:
        for (j = 0; j < 4; j++)
            output[j + (i * 4)] = statePrt[j][i];
}

int main()
{
    uchar key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uchar in[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uchar out[16];
    uchar out2[16];

    printHex(in);
    AES_ECB(key, in, out, 0);
    AES_ECB(key, out, out2, 5);
    printHex(out);
    printHex(out2);
    return 0;
}

/*
void AES_ECB_encrypt(uint8_t *aesKey, uint8_t *input, uint8_t *output)
{

    // https://docs.xilinx.com/r/en-US/ug1399-vitis-hls/pragma-HLS-array_partition
#pragma HLS ARRAY_PARTITION variable = sbox dim = 0 complete
    // #pragma HLS ARRAY_PARTITION variable = rsbox dim = 0 complete

    volatile uchar RoundKey[(Nr + 1) * Nb * 4]; // Rounds + Key(1) * 16
#pragma HLS ARRAY_PARTITION variable = RoundKey dim = 0 complete
    KeyExpansion(aesKey, RoundKey);
    volatile uchar statePrt[4][4];
#pragma HLS ARRAY_PARTITION variable = statePrt dim = 0 complete

    uchar i = 0;
    uchar j = 0;

    // As per Cipher Example Appendix B

AES_ECB_encryptLoop1:
    for (i = 0; i < 4; i++)
    AES_ECB_encryptLoop2:
        for (j = 0; j < 4; j++)
            statePrt[j][i] = input[j + (i * 4)];

    Cipher(statePrt, (uchar *)(&RoundKey));

    // Copy the result back to out

AES_ECB_encryptLoop3:
    for (i = 0; i < 4; i++)
    AES_ECB_encryptLoop4:
        for (j = 0; j < 4; j++)
            output[j + (i * 4)] = statePrt[j][i];
}
*/

// https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901427
// file:///C:/Users/claud/Downloads/ug1399-vitis-hls-en-us-2022.2.pdf
// https://github.com/kokke/tiny-AES-c
