#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <chrono>
#include <ctime>
#include "aes.h"

#define DEBUG 0

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

#ifdef DEBUG
static void printToFile(std::fstream &outFile, uchar *value)
{
    std::stringstream hexValue;
    for (int i = 0; i < 16; ++i)
    {
        hexValue << std::hex << std::setfill('0') << std::setw(2) << (int)value[i];
    }
    outFile << hexValue.str() << std::endl;
}
#endif

static int executeEncryptionDecryptionTest(std::string fileName, int mode)
{

#ifdef DEBUG
    std::fstream outFile;
    outFile.open("D:\\Master\\Sem_3\\FPGA\\Proiect\\AES\\Sources\\debugFile.txt", std::ofstream::out | std::ios_base::app);
    auto now = std::chrono::system_clock::now();
    std::time_t timeNow = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&timeNow);
    // Timestamp like 2023-01-29 22:51:25
    outFile << "Timestamp:\t"
            << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << std::endl;

    int round = 0;
#endif

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

            if (mode == 0)
            {
                // Encryption
                // Key is the encryption key, goldenInput is the desired output
                // output is the output produced by the function and mode is encryption or decryption

                AES_ECB(key, goldenInput, output, mode);
                // Here, because this is encryption we compare the output to the desired goldenOutput.
                returnValue += checkEquals(output, goldenOutput);

#ifdef DEBUG
                round++;
                outFile << round << std::endl;
                outFile << "Enc_Input:\t";
                printToFile(outFile, goldenInput);
                outFile << "Enc_OutG:\t";
                printToFile(outFile, goldenOutput);
                outFile << "Enc_Out:\t";
                printToFile(outFile, output);
#endif
            }
            else
            {
                // Decryption
                AES_ECB(key, goldenOutput, output, mode);
                // Here, because this is decryption we compare the output to the input that produces that encryption.
                returnValue += checkEquals(goldenInput, output);
#ifdef DEBUG
                round++;
                outFile << round << std::endl;
                outFile << "Dec_Input:\t";
                printToFile(outFile, goldenOutput);
                outFile << "Dec_OutG:\t";
                printToFile(outFile, goldenInput);
                outFile << "Dec_Out:\t";
                printToFile(outFile, output);
#endif
            }
        }
#ifdef DEBUG
        outFile << "" << std::endl;
        outFile << "" << std::endl;
        outFile.close();
#endif

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
    int returnValue = executeEncryptionDecryptionTest("D:\\Master\\Sem_3\\FPGA\\Proiect\\AES\\Sources\\goldenValues.txt", 0);
    returnValue += executeEncryptionDecryptionTest("D:\\Master\\Sem_3\\FPGA\\Proiect\\AES\\Sources\\goldenValues.txt", 1);
    return returnValue;
}
