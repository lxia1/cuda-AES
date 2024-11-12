#ifndef __COMMON_CUH__
#define __COMMON_CUH__

#include <cuda_runtime.h>

__device__ void KeyExpansion(const unsigned char *key, unsigned char *roundKeys);
__device__ unsigned char xtime(unsigned char x);

#endif