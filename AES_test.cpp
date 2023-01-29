#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "aes.h"

static void printHex(uint8_t *str)
{
    unsigned char i;
    for (i = 0; i < 16; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

static int checkEquals(uchar *target, uchar *destination)
{
    for (int i = 0; i < 16; i++)
        if (target[i] != destination[i])
            return 1;
    return 0;
}

static int executeEncryptionDecryptionTest(std::string fileName, int mode)
{

    int returnValue = 0;
    uchar key[16], goldenInput[16], goldenOutput[16], output[16];
    std::string line;
    std::fstream file;
    file.open(fileName);

    if (file.is_open())
    {
        std::stringstream ss(line);
        std::getline(file, line);
        // The key is the first line of the file
        // Next is only the goldenInput and goldenOutput
        for (int i = 0; i < 16; i++)
        {
            std::string byte = line.substr(i * 2, 2);
            key[i] = (uchar)strtol(byte.c_str(), nullptr, 16);
        }

        while (std::getline(file, line))
        {
            ss.clear();
            ss.str(line);

            for (int i = 0; i < 16; i++)
            {
                std::string byte = line.substr(i * 2, 2);
                goldenInput[i] = (uchar)strtol(byte.c_str(), nullptr, 16);
            }

            std::getline(file, line);
            ss.clear();
            ss.str(line);

            for (int i = 0; i < 16; i++)
            {
                std::string byte = line.substr(i * 2, 2);
                goldenOutput[i] = (uchar)strtol(byte.c_str(), nullptr, 16);
            }

            if (!mode)
            {
                // Encryption
                // Key is the encryption key, goldenInput is the desired output
                // output is the output produced by the function and mode is encryption or decryption

                AES_ECB(key, goldenInput, output, mode);
                // Here, because this is encryption we compare the output to the desired goldenOutput.
                returnValue += checkEquals(output, goldenOutput);
            }
            else
            {
                // Decryption
                AES_ECB(key, goldenOutput, output, mode);
                // Here, because this is decryption we compare the output to the input that produces that encryption.
                returnValue += checkEquals(goldenInput, output);
            }
        }
        file.close();
    }
    else
        std::cout << "Unable to open file" << std::endl;

    return returnValue;
}

int main()
{
    // Each test will return 0 or 1, if all are 0 then all tests are correct, thare are 7 pairs of plain an cipher
    // Which makes a total of 14 tests (7 for enc and 7 for dec)
    return executeEncryptionDecryptionTest("D:\\Master\\Sem_3\\FPGA\\Proiect\\AES\\Sources\\goldenValues.txt", 0) +
           executeEncryptionDecryptionTest("D:\\Master\\Sem_3\\FPGA\\Proiect\\AES\\Sources\\goldenValues.txt", 1);
}
