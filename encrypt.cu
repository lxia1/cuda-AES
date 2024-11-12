#include <cuda_runtime.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include "constants.cuh"
#include "common.cuh"

__device__ void SubBytes(unsigned char *state)
{
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        state[i] = sbox[state[i]];
    }
}

__device__ void ShiftRows(unsigned char *state)
{
    unsigned char temp;

    // Rotate first row 1 columns to left
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Rotate second row 2 columns to left
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Rotate third row 3 columns to left
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

__device__ void MixColumns(unsigned char *state)
{
    unsigned char Tmp, Tm, t;
    for (int i = 0; i < 4; ++i)
    {
        t = state[i * 4];
        Tmp = state[i * 4] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ state[i * 4 + 3];
        Tm = state[i * 4] ^ state[i * 4 + 1];
        Tm = xtime(Tm);
        state[i * 4] ^= Tm ^ Tmp;
        Tm = state[i * 4 + 1] ^ state[i * 4 + 2];
        Tm = xtime(Tm);
        state[i * 4 + 1] ^= Tm ^ Tmp;
        Tm = state[i * 4 + 2] ^ state[i * 4 + 3];
        Tm = xtime(Tm);
        state[i * 4 + 2] ^= Tm ^ Tmp;
        Tm = state[i * 4 + 3] ^ t;
        Tm = xtime(Tm);
        state[i * 4 + 3] ^= Tm ^ Tmp;
    }
}

__device__ void AddRoundKey(unsigned char *state, unsigned char *roundKey)
{
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        state[i] ^= roundKey[i];
    }
}

__device__ void aes_encrypt_block(unsigned char *input, unsigned char *output, unsigned char *key)
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
    AddRoundKey(state, roundKeys);

    // Main rounds
    for (int round = 1; round < AES_NUM_ROUNDS; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * AES_BLOCK_SIZE);
    }

    // Final round
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + AES_NUM_ROUNDS * AES_BLOCK_SIZE);

    // Copy state to output
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        output[i] = state[i];
    }
}

__global__ void aes_encrypt(unsigned char *input, unsigned char *output, unsigned char *key, size_t size)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx * AES_BLOCK_SIZE < size)
    {
        aes_encrypt_block(&input[idx * AES_BLOCK_SIZE], &output[idx * AES_BLOCK_SIZE], key);
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

void pkcs7_pad(std::vector<unsigned char> &buffer)
{
    size_t padding_size = AES_BLOCK_SIZE - (buffer.size() % AES_BLOCK_SIZE);
    buffer.insert(buffer.end(), padding_size, static_cast<unsigned char>(padding_size));
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

    pkcs7_pad(input_data);

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

    aes_encrypt<<<num_blocks, block_size>>>(d_input, d_output, d_key, padded_size);

    cudaMemcpy(output_data.data(), d_output, padded_size, cudaMemcpyDeviceToHost);

    write_file(output_file, output_data);

    cudaFree(d_input);
    cudaFree(d_output);
    cudaFree(d_key);

    // Get the end time
    auto end = std::chrono::high_resolution_clock::now();
    // Calculate the duration in milliseconds
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Print the duration in milliseconds
    std::cout << "AES encryption time: " << duration.count() << "ms" << std::endl;
    return 0;
}