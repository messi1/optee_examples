#include "symmetric_key_ops.h"

/* AES key size */
#define AES_SECURE_STORAGE_KEY_SIZE 16u /* 128 bits */

/* Maximum key ID length */
#define AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH 64u
#define AES_SECURE_STORAGE_MAX_BUFFER_LENGTH 4096u

/*
 * Generate a secure random key and store it in secure storage
 */
TEE_Result generateKey( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result       res           = TEE_SUCCESS;
    TEE_ObjectHandle keyObj        = TEE_HANDLE_NULL;
    TEE_ObjectHandle persistentKey = TEE_HANDLE_NULL;
    memref           keyId         = { 0 };

    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE );
    /* Check parameters */
    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Get the key ID from parameters safely */
    res = dupParamMemory( &keyId, &params[0], AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH );
    if ( res != TEE_SUCCESS )
    {
        return res;
    }

    /* Create a transient object to generate the key */
    res =
        TEE_AllocateTransientObject( TEE_TYPE_AES, N_BITS( AES_SECURE_STORAGE_KEY_SIZE ), &keyObj );
    if ( res != TEE_SUCCESS )
    {
        keyObj = TEE_HANDLE_NULL;
        goto out;
    }

    /* Generate a random key */
    res = TEE_GenerateKey( keyObj, N_BITS( AES_SECURE_STORAGE_KEY_SIZE ), NULL, 0 );
    if ( res != TEE_SUCCESS )
    {
        goto out;
    }

    /* Create or open the persistent object for the key */
    res = TEE_CreatePersistentObject( TEE_STORAGE_PRIVATE, keyId.buffer, keyId.size,
                                      TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ
                                          | TEE_DATA_FLAG_ACCESS_WRITE_META,
                                      keyObj, NULL, 0, &persistentKey );
    if ( res != TEE_SUCCESS )
    {
        goto out;
    }

    TEE_CloseObject( persistentKey );
    persistentKey = TEE_HANDLE_NULL;

out:
    TEE_FreeTransientObject( keyObj );
    destroyMemref( &keyId );
    return res;
}

/*
 * Delete a key from secure storage
 */
TEE_Result deleteKey( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result       res;
    TEE_ObjectHandle keyObj = TEE_HANDLE_NULL;
    memref           keyId  = { 0 };

    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE );
    /* Check parameters */
    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Get the key ID from parameters safely */
    res = dupParamMemory( &keyId, &params[0], AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH );
    if ( res != TEE_SUCCESS )
    {
        return res;
    }

    /* Open the persistent object for the key */
    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, keyId.buffer, keyId.size,
                                    TEE_DATA_FLAG_ACCESS_WRITE_META, &keyObj );
    if ( res != TEE_SUCCESS )
    {
        goto out;
    }

    /* Delete the object */
    res = TEE_CloseAndDeletePersistentObject1( keyObj );
    if ( res != TEE_SUCCESS )
    {
        IMSG( "Could not delete persistent object\n" );
        goto out;
    }
    keyObj = TEE_HANDLE_NULL;

out:
    TEE_CloseObject( keyObj );
    destroyMemref( &keyId );
    return res;
}

/*
 * Initialize AES-CTR context with the key from secure storage
 */
TEE_Result initAesCtrContext( AesCtrContext* ctx, memref keyId, uint32_t mode )
{
    TEE_Result       res;
    TEE_ObjectHandle keyObj = TEE_HANDLE_NULL;

    if ( keyId.buffer == NULL || keyId.size == 0
         || keyId.size > AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH || ctx == NULL )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Open the persistent object for the key */
    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, keyId.buffer, keyId.size,
                                    TEE_DATA_FLAG_ACCESS_READ, &keyObj );
    if ( res != TEE_SUCCESS )
    {
        goto out_error;
    }

    /* Allocate operation for AES-CTR mode */
    res = TEE_AllocateOperation( &ctx->op, TEE_ALG_AES_CTR, mode,
                                 N_BITS( AES_SECURE_STORAGE_KEY_SIZE ) );
    if ( res != TEE_SUCCESS )
    {
        goto out_error;
    }

    /* Set the key for the operation */
    res = TEE_SetOperationKey( ctx->op, keyObj );
    if ( res != TEE_SUCCESS )
    {
        goto out_error;
    }

    /* The key is copied to the operation and can be freed */
    TEE_CloseObject( keyObj );
    keyObj = TEE_HANDLE_NULL;

    /* Generate a random initialization vector */
    TEE_GenerateRandom( ctx->iv, AES_SECURE_STORAGE_BLOCK_SIZE );

    return res;

out_error:
    TEE_FreeOperation( ctx->op );
    ctx->op = TEE_HANDLE_NULL;
    TEE_CloseObject( keyObj );
    return res;
}

/*
 * Free AES-CTR context
 */
void destroyAesCtrContext( AesCtrContext* ctx )
{
    if ( ctx )
    {
        TEE_FreeOperation( ctx->op );
        ctx->op = TEE_HANDLE_NULL;
    }
}

/*
 * Encrypt a buffer with AES-CTR
 */
TEE_Result encryptBuffer( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result    res;
    AesCtrContext ctx     = { .op = TEE_HANDLE_NULL };
    memref        keyId   = { 0 };
    memref        inData  = { 0 };
    memref        outData = { 0 };

    uint32_t exp_param_types =
        TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                         TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT );

    /* Check parameters */
    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Get the key ID from parameters safely */
    res = dupParamMemory( &keyId, &params[0], AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH );
    if ( res != TEE_SUCCESS )
    {
        return res;
    }

    /* Get the plain text parameters safely */
    res = dupParamMemory( &inData, &params[1], AES_SECURE_STORAGE_MAX_BUFFER_LENGTH );
    if ( res != TEE_SUCCESS )
    {
        goto out;
    }

    /* Read the output buffer parameter */
    outData.buffer = params[2].memref.buffer;
    outData.size   = params[2].memref.size;
    if ( outData.buffer == NULL
         || outData.size < ( inData.size + 2 * AES_SECURE_STORAGE_BLOCK_SIZE ) )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Initialize AES-CTR context */
    res = initAesCtrContext( &ctx, keyId, TEE_MODE_ENCRYPT );
    if ( res != TEE_SUCCESS )
    {
        goto out;
    }

    /* First, copy IV to the beginning of output buffer */
    TEE_MemMove( outData.buffer, ctx.iv, AES_SECURE_STORAGE_BLOCK_SIZE );

    /* Initialize the encryption operation */
    TEE_CipherInit( ctx.op, ctx.iv, AES_SECURE_STORAGE_BLOCK_SIZE );

    /* Encrypt the data */
    uint32_t destLen = outData.size - AES_SECURE_STORAGE_BLOCK_SIZE;
    res =
        TEE_CipherDoFinal( ctx.op, inData.buffer, inData.size,
                           ( (uint8_t*)outData.buffer ) + AES_SECURE_STORAGE_BLOCK_SIZE, &destLen );
    if ( res != TEE_SUCCESS )
    {
        goto out;
    }

    /* Set the actual output size (IV + encrypted data) */
    params[3].value.a = destLen + AES_SECURE_STORAGE_BLOCK_SIZE;

out:
    destroyAesCtrContext( &ctx );
    destroyMemref( &inData );
    destroyMemref( &keyId );
    return res;
}

/*
 * Decrypt a buffer with AES-CTR
 */
TEE_Result decryptBuffer( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result    res;
    AesCtrContext ctx     = { .op = TEE_HANDLE_NULL };
    memref        keyId   = { 0 };
    memref        inData  = { 0 };
    memref        outData = { 0 };

    uint32_t exp_param_types =
        TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                         TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT );

    /* Check parameters */
    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Get the key ID from parameters safely */
    res = dupParamMemory( &keyId, &params[0], AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH );
    if ( res != TEE_SUCCESS )
    {
        goto out;
    }

    /* Get the encrypted text parameters safely */
    res = dupParamMemory( &inData, &params[1], AES_SECURE_STORAGE_MAX_BUFFER_LENGTH );
    if ( res != TEE_SUCCESS )
    {
        goto out;
    }

    if ( inData.size < AES_SECURE_STORAGE_BLOCK_SIZE )
    {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto out;
    }

    /* Get parameters */
    outData.buffer = params[2].memref.buffer;
    outData.size   = params[2].memref.size;
    if ( outData.buffer == NULL || outData.size < inData.size - AES_SECURE_STORAGE_BLOCK_SIZE )
    {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto out;
    }

    /* Initialize AES-CTR context */
    res = initAesCtrContext( &ctx, keyId, TEE_MODE_DECRYPT );
    if ( res != TEE_SUCCESS )
    {
        goto out;
    }

    /* Extract IV from the beginning of input data */
    TEE_MemMove( ctx.iv, inData.buffer, AES_SECURE_STORAGE_BLOCK_SIZE );

    /* Initialize the decryption operation */
    TEE_CipherInit( ctx.op, ctx.iv, AES_SECURE_STORAGE_BLOCK_SIZE );

    /* Decrypt the data (skipping the IV) */
    uint32_t destLen = outData.size;
    res =
        TEE_CipherDoFinal( ctx.op, ( (uint8_t*)inData.buffer ) + AES_SECURE_STORAGE_BLOCK_SIZE,
                           inData.size - AES_SECURE_STORAGE_BLOCK_SIZE, outData.buffer, &destLen );
    if ( res != TEE_SUCCESS )
    {
        goto out;
    }

    /* Set the actual output size */
    params[3].value.a = destLen;

out:
    destroyAesCtrContext( &ctx );
    destroyMemref( &inData );
    destroyMemref( &keyId );
    return res;
}