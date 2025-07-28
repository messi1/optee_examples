// Copyright (c) 2025 Franke

#ifndef TEE_UTILS_H
#define TEE_UTILS_H

#include <tee_api.h>

#define N_BITS( BYTES ) ( (BYTES)*8 )

typedef struct
{
    void*  buffer;
    size_t size;
} memref;

/**
 * Destroys a memref structure
 *
 * Frees the memory allocated for the buffer and resets the size to 0.
 * The memref structure itself is not freed.
 * TEE_Free is used to free the memory.
 *
 * @param ref          Memref to be destroyed
 */
void destroyMemref( memref* ref );

/**
 * Safely copies a memory block from TEE parameters
 * 
 * @param dest          Memref whose pointer will be set to the newly allocated memory
 * @param param         TEE_Param source reference
 * @param max_size      Maximum allowed size (0 for no limit)
 * 
 * @return TEE_SUCCESS on success, otherwise an error code
 *
 * @note On success the funtion allocates memory for the destination
 * buffer that needs to be freed by the caller.
 */
TEE_Result dupParamMemory( memref* dest, const TEE_Param* param, size_t max_size );


#endif /* TEE_UTILS_H */
