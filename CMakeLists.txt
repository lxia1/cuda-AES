cmake_minimum_required(VERSION 3.10)

# Set policy CMP0104 to NEW
if(POLICY CMP0104)
  cmake_policy(SET CMP0104 NEW)
endif()
# Set C++17 standard for CUDA
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

# Set C++17 standard for C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set CUDA architectures (adjust according to your GPU)
set(CMAKE_CUDA_ARCHITECTURES 60)

# Set the project name
project(AES_CUDA LANGUAGES CXX CUDA)

# Find CUDA package
find_package(CUDA REQUIRED)

# Set the CUDA architecture (modify according to your GPU)
set(CUDA_ARCHITECTURE "sm_50")
# Enable relocatable device code
set(CUDA_NVCC_FLAGS "${CUDA_NVCC_FLAGS} -rdc=true")

# Set the source files for encryption and decryption
set(ENCRYPTION_SOURCES
    encrypt.cu 
    common.cu
)

set(DECRYPTION_SOURCES
    decrypt.cu 
    common.cu
)

# Add the encryption executable
cuda_add_executable(encrypt ${ENCRYPTION_SOURCES})
target_compile_options(encrypt PRIVATE -arch=${CUDA_ARCHITECTURE})
set_target_properties(encrypt PROPERTIES CUDA_SEPARABLE_COMPILATION ON)

# Add the decryption executable
cuda_add_executable(decrypt ${DECRYPTION_SOURCES})
target_compile_options(decrypt PRIVATE -arch=${CUDA_ARCHITECTURE})
set_target_properties(decrypt PROPERTIES CUDA_SEPARABLE_COMPILATION ON)

# Include directories
# include_directories(${CMAKE_SOURCE_DIR}/include)

# Link libraries
# target_link_libraries(encrypt ${CUDA_LIBRARIES})
# target_link_libraries(decrypt ${CUDA_LIBRARIES})