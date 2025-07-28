#ifndef SYMMETRIC_KEY_OPS_H
#define SYMMETRIC_KEY_OPS_H

#include <tee_internal_api.h>
#include "TeeUtils.h"

/* AES block size */
#define AES_SECURE_STORAGE_BLOCK_SIZE 16u /* 128 bits */

typedef struct
{
    TEE_OperationHandle op;
    uint8_t             iv[AES_SECURE_STORAGE_BLOCK_SIZE]; /* Initial vector */
} AesCtrContext;

/*
 * Generate a secure random key and store it in secure storage
 */
TEE_Result generateKey( uint32_t param_types, TEE_Param params[4] );

/*
 * Delete a key from secure storage
 */
TEE_Result deleteKey( uint32_t param_types, TEE_Param params[4] );

/*
 * Initialize AES-CTR context with the key from secure storage
 */
TEE_Result initAesCtrContext( AesCtrContext* ctx, memref keyId, uint32_t mode );

/*
 * Free AES-CTR context
 */
void destroyAesCtrContext( AesCtrContext* ctx );

/*
 * Encrypt a buffer with AES-CTR
 */
TEE_Result encryptBuffer( uint32_t param_types, TEE_Param params[4] );

/*
 * Decrypt a buffer with AES-CTR
 */
TEE_Result decryptBuffer( uint32_t param_types, TEE_Param params[4] );

#endif /* SYMMETRIC_KEY_OPS_H */