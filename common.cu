#include "common.cuh"
#include "constants.cuh"

__device__ void KeyExpansion(const unsigned char *key, unsigned char *roundKeys)
{
    unsigned char temp[4];
    int i = 0;

    // The first round key is the key itself
    for (i = 0; i < AES_KEY_SIZE; ++i)
    {
        roundKeys[i] = key[i];
    }

    // All other round keys are found from the previous round keys
    for (i = AES_KEY_SIZE; i < AES_BLOCK_SIZE * (AES_NUM_ROUNDS + 1); i += 4)
    {
        // Copy the previous word
        for (int j = 0; j < 4; ++j)
        {
            temp[j] = roundKeys[(i - 4) + j];
        }

        // Every 4th word, apply the core schedule to temp
        if (i % AES_KEY_SIZE == 0)
        {
            // Rotate the word
            unsigned char k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            // Apply S-box
            for (int j = 0; j < 4; ++j)
            {
                temp[j] = sbox[temp[j]];
            }

            // XOR with Rcon
            temp[0] ^= (0x01 << ((i / AES_KEY_SIZE) - 1));
        }

        // XOR with the word 4 positions earlier
        for (int j = 0; j < 4; ++j)
        {
            roundKeys[i + j] = roundKeys[i + j - AES_KEY_SIZE] ^ temp[j];
        }
    }
}

__device__ unsigned char xtime(unsigned char x)
{
    return (x << 1) ^ ((x >> 7) * 0x1b);
}