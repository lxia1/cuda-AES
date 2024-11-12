# AES Encryption and Decryption Tools with CUDA

This project provides tools for AES encryption and decryption using CUDA. The tools are designed to encrypt and decrypt binary input files using a 128-bit key.

## Description

The AES encryption and decryption tools leverage the parallel processing capabilities of CUDA to accelerate the encryption and decryption processes. The tools use a simplified version of the AES-128 algorithm, which operates on 16-byte blocks of data. The key features of the design are:

- **Parallel Processing**: The encryption and decryption of data blocks are parallelized using CUDA, allowing for faster processing on compatible NVIDIA GPUs.
- **PKCS#7 Padding**: The input data is padded using the PKCS#7 padding scheme to ensure that its size is a multiple of the AES block size (16 bytes). This padding is removed after decryption to restore the original data.
- **Key Management**: The encryption and decryption keys are read from a specified key file, which must contain exactly 16 bytes (128 bits) of key data.
- **File I/O**: The tools read the input data from a file, process it using CUDA, and write the output data to a file.

## Prerequisites

- CUDA Toolkit (version 12.4 or later)
- CMake (version 3.10 or later)
- Nvidia nvcc compiler 

## Building the Project

1. **Clone the repository**:

    ```sh
    git clone <repository_url>
    cd <repository_directory>
    ```

2. **Create a build directory**:

    ```sh
    mkdir build
    cd build
    ```

3. **Run CMake to configure the project**:

    ```sh
    cmake ..
    ```

4. **Build the project**:

    ```sh
    make
    ```

This will generate two executables: `encrypt` and `decrypt`.

## Usage

### Encryption

To encrypt a file, use the `encrypt` tool:

```
./encrypt <input file> <output file> <key file>
```
input file: The path to the input file to be encrypted.
output file: The path to the output file where the encrypted data will be saved.
key file: The path to the key file containing a 128-bit (16 bytes) key.

#### Example:
```
./encrypt input.txt encrypted.bin key.txt
```

### Decryption

To decrypt a file, use the decrypt tool:

```
./decrypt <input file> <output file> <key file>
```

input file: The path to the input file to be decrypted.
output file: The path to the output file where the decrypted data will be saved.
key file: The path to the key file containing a 128-bit (16 bytes) key.

#### Example:
```
./decrypt encrypted.bin decrypted.txt key.txt
```

### Key File Format

The key file should contain exactly 16 bytes (128 bits) of key data. Ensure that the key file is in binary format and not in text format.
#### Example
Create a key file with 16 bytes of data:
```
echo -n "1234567890abcdef" > key.txt
```

Encrypt a text file:
```
./encrypt input.txt encrypted.bin key.txt
```

Decrypt the encrypted file:
```
./decrypt encrypted.bin decrypted.txt key.txt
```

## License
This project is licensed under the MIT License. See the LICENSE file for details.
### Acknowledgments
The AES encryption and decryption algorithms are simplified for demonstration purposes. For a complete and secure implementation, refer to the official AES specification.
CUDA is a parallel computing platform and application programming interface (API) model created by Nvidia.