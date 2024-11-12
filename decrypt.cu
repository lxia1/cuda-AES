#include <cuda_runtime.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <chrono>
#include "constants.cuh"
#include "common.cuh"

__device__ unsigned char Multiply(unsigned char x, unsigned char y)
{
    return (((y & 1) * x) ^
            ((y >> 1 & 1) * xtime(x)) ^
            ((y >> 2 & 1) * xtime(xtime(x))) ^
            ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
            ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

__device__ void InvSubBytes(unsigned char *state)
{
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        state[i] = rsbox[state[i]];
    }
}

__device__ void InvShiftRows(unsigned char *state)
{
    unsigned char temp;

    // Rotate first row 1 columns to right
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // Rotate second row 2 columns to right
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Rotate third row 3 columns to right
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

__device__ void InvMixColumns(unsigned char *state)
{
    unsigned char a, b, c, d;
    for (int i = 0; i < 4; ++i)
    {
        a = state[i * 4];
        b = state[i * 4 + 1];
        c = state[i * 4 + 2];
        d = state[i * 4 + 3];

        state[i * 4] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        state[i * 4 + 1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        state[i * 4 + 2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        state[i * 4 + 3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}

__device__ void AddRoundKey(unsigned char *state, unsigned char *roundKey)
{
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        state[i] ^= roundKey[i];
    }
}

__device__ void aes_decrypt_block(unsigned char *input, unsigned char *output, unsigned char *key)
{
    unsigned char state[AES_BLOCK_SIZE];
    unsigned char roundKeys[AES_BLOCK_SIZE * (AES_NUM_ROUNDS + 1)];

    // Copy input to state
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        state[i] = input[i];
    }

    // Key expansion
    KeyExpansion(key, roundKeys);

    // Initial round
    AddRoundKey(state, roundKeys + AES_NUM_ROUNDS * AES_BLOCK_SIZE);

    // Main rounds
    for (int round = AES_NUM_ROUNDS - 1; round > 0; --round)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * AES_BLOCK_SIZE);
        InvMixColumns(state);
    }

    // Final round
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);

    // Copy state to output
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        output[i] = state[i];
    }
}

__global__ void aes_decrypt(unsigned char *input, unsigned char *output, unsigned char *key, size_t size)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx * AES_BLOCK_SIZE < size)
    {
        aes_decrypt_block(&input[idx * AES_BLOCK_SIZE], &output[idx * AES_BLOCK_SIZE], key);
    }
}

void read_file(const char *filename, std::vector<unsigned char> &buffer)
{
    std::ifstream file(filename, std::ios::binary);
    if (file.is_open())
    {
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        buffer.resize(size);
        file.read(reinterpret_cast<char *>(buffer.data()), size);
        file.close();
    }
    else
    {
        std::cerr << "Error: Could not open file " << filename << std::endl;
    }
}

void write_file(const char *filename, const std::vector<unsigned char> &buffer)
{
    std::ofstream file(filename, std::ios::binary);
    if (file.is_open())
    {
        file.write(reinterpret_cast<const char *>(buffer.data()), buffer.size());
        file.close();
    }
    else
    {
        std::cerr << "Error: Could not open file " << filename << std::endl;
    }
}

void pkcs7_unpad(std::vector<unsigned char> &buffer)
{
    if (!buffer.empty())
    {
        size_t padding_size = buffer.back();
        if (padding_size <= AES_BLOCK_SIZE && padding_size <= buffer.size())
        {
            buffer.resize(buffer.size() - padding_size);
        }
    }
}

void read_key(const char *filename, std::vector<unsigned char> &key)
{
    std::ifstream file(filename, std::ios::binary);
    if (file.is_open())
    {
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        key.resize(size);
        file.read(reinterpret_cast<char *>(key.data()), size);
        file.close();
    }
    else
    {
        std::cerr << "Error: Could not open key file " << filename << std::endl;
    }
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <input file> <output file> <key file>" << std::endl;
        return 1;
    }
    // Get the start time
    auto start = std::chrono::high_resolution_clock::now();

    const char *input_file = argv[1];
    const char *output_file = argv[2];
    const char *key_file = argv[3];

    std::vector<unsigned char> input_data;
    read_file(input_file, input_data);

    std::vector<unsigned char> key;
    read_key(key_file, key);

    if (key.size() != AES_BLOCK_SIZE)
    {
        std::cerr << "Error: Key size must be " << AES_BLOCK_SIZE << " bytes" << std::endl;
        return 1;
    }

    size_t padded_size = input_data.size();
    std::vector<unsigned char> output_data(padded_size);

    unsigned char *d_input;
    unsigned char *d_output;
    unsigned char *d_key;

    cudaMalloc(&d_input, padded_size);
    cudaMalloc(&d_output, padded_size);
    cudaMalloc(&d_key, AES_BLOCK_SIZE);

    cudaMemcpy(d_input, input_data.data(), padded_size, cudaMemcpyHostToDevice);
    cudaMemcpy(d_key, key.data(), AES_BLOCK_SIZE, cudaMemcpyHostToDevice);

    int block_size = 256;
    int num_blocks = (padded_size / AES_BLOCK_SIZE + block_size - 1) / block_size;

    aes_decrypt<<<num_blocks, block_size>>>(d_input, d_output, d_key, padded_size);

    cudaMemcpy(output_data.data(), d_output, padded_size, cudaMemcpyDeviceToHost);

    pkcs7_unpad(output_data);

    write_file(output_file, output_data);

    cudaFree(d_input);
    cudaFree(d_output);
    cudaFree(d_key);

    // Get the end time
    auto end = std::chrono::high_resolution_clock::now();
    // Calculate the duration in milliseconds
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Print the duration in milliseconds
    std::cout << "AES decryption time: " << duration.count() << "ms" << std::endl;
    return 0;
}