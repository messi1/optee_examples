/*
 * Copyright (c) 2025, AES Secure Storage TA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <aes_secure_storage_ta.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/*
 * AES-CTR implementation with secure key storage functionality
 */
struct aes_ctr_ctx
{
    TEE_OperationHandle op;
    uint8_t             iv[AES_KEY_SIZE]; /* Initial vector */
};

/**
 * Safely copies a memory block from TEE parameters
 * 
 * @param param         TEE_Param source reference
 * @param buffer        Destination pointer that will be set to the newly allocated memory
 * @param buffer_size   Pointer to variable that will receive the size of the buffer
 * @param max_size      Maximum allowed size (0 for no limit)
 * 
 * @return TEE_SUCCESS on success, otherwise an error code
 */
static TEE_Result safe_copy_param_mem( const TEE_Param* param, const char** buffer,
                                       size_t* buffer_size, size_t max_size )
{
    size_t size = param->memref.size;
    void*  src  = param->memref.buffer;

    /* Validate parameters */
    if ( param->memref.buffer == NULL || param->memref.size == 0 )
        return TEE_ERROR_BAD_PARAMETERS;

    /* Check maximum size if specified */
    if ( max_size > 0 && size > max_size )
        return TEE_ERROR_BAD_PARAMETERS;

    /* Allocate memory */
    void* dst = TEE_Malloc( size, 0 );
    if ( ! dst )
        return TEE_ERROR_OUT_OF_MEMORY;

    /* Copy data */
    TEE_MemMove( dst, src, size );

    /* Set output parameters */
    *buffer      = dst;
    *buffer_size = size;

    return TEE_SUCCESS;
}

/*
 * Generate a secure random key and store it in secure storage
 */
static TEE_Result generate_and_store_key( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result       res;
    TEE_ObjectHandle key_obj       = TEE_HANDLE_NULL;
    TEE_ObjectHandle transient_obj = TEE_HANDLE_NULL;
    uint8_t          key_data[AES_KEY_SIZE];
    const char*      key_id;
    size_t           key_id_len;
    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE );

    /* Check parameters */
    if ( param_types != exp_param_types )
        return TEE_ERROR_BAD_PARAMETERS;

    /* Get the key ID from parameters safely */
    res = safe_copy_param_mem( &params[0], &key_id, &key_id_len, MAX_KEY_ID_LENGTH );
    if ( res != TEE_SUCCESS )
        return res;

    /* Create a transient object to generate the key */
    res = TEE_AllocateTransientObject( TEE_TYPE_AES, AES_KEY_SIZE * 8, &transient_obj );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Generate a random key */
    res = TEE_GenerateKey( transient_obj, AES_KEY_SIZE * 8, NULL, 0 );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Extract the key value from the transient object */
    TEE_GetObjectBufferAttribute( transient_obj, TEE_ATTR_SECRET_VALUE, key_data,
                                  &( uint32_t ){ AES_KEY_SIZE } );

    /* Create or open the persistent object for the key */
    res = TEE_CreatePersistentObject( TEE_STORAGE_PRIVATE, key_id, key_id_len,
                                      TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ
                                          | TEE_DATA_FLAG_ACCESS_WRITE_META,
                                      TEE_HANDLE_NULL, key_data, AES_KEY_SIZE, &key_obj );
    if ( res != TEE_SUCCESS )
        goto exit;

exit:
    if ( transient_obj != TEE_HANDLE_NULL )
        TEE_FreeTransientObject( transient_obj );
    if ( key_obj != TEE_HANDLE_NULL )
        TEE_CloseObject( key_obj );

    return res;
}

/*
 * Store a specific key in secure storage
 */
static TEE_Result set_key( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result       res;
    TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
    const char*      key_id;
    size_t           key_id_len;
    const uint8_t*   key_data;
    size_t           key_data_len;
    uint32_t         exp_param_types =
        TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                         TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE );

    /* Check parameters */
    if ( param_types != exp_param_types )
        return TEE_ERROR_BAD_PARAMETERS;

    /* Get the key ID from parameters safely */
    res = safe_copy_param_mem( &params[0], &key_id, &key_id_len, MAX_KEY_ID_LENGTH );
    if ( res != TEE_SUCCESS )
        return res;

    key_data     = params[1].memref.buffer;
    key_data_len = params[1].memref.size;

    if ( key_data == NULL || key_data_len != AES_KEY_SIZE )
        return TEE_ERROR_BAD_PARAMETERS;

    /* Delete any existing key with the same ID */
    TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, key_id, key_id_len,
                              TEE_DATA_FLAG_ACCESS_WRITE_META, &key_obj );
    if ( key_obj != TEE_HANDLE_NULL )
    {
        TEE_CloseAndDeletePersistentObject1( key_obj );
        key_obj = TEE_HANDLE_NULL;
    }

    /* Create a new persistent object for the key */
    res = TEE_CreatePersistentObject( TEE_STORAGE_PRIVATE, key_id, key_id_len,
                                      TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ
                                          | TEE_DATA_FLAG_ACCESS_WRITE_META
                                          | TEE_DATA_FLAG_SHARE_READ,
                                      TEE_HANDLE_NULL, key_data, key_data_len, &key_obj );
    if ( res != TEE_SUCCESS )
        goto exit;
exit:
    if ( key_obj != TEE_HANDLE_NULL )
        TEE_CloseObject( key_obj );

    return res;
}

/*
 * Retrieve a key from secure storage
 */
static TEE_Result get_key( uint32_t param_types, TEE_Param params[4] )
{
    TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
    TEE_Result       res;
    const char*      key_id = NULL;
    size_t           key_id_len;
    uint8_t*         key_data = NULL;
    uint32_t         key_data_len;
    const uint32_t   exp_param_types =
        TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                         TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE );

    /* Check parameters */
    if ( param_types != exp_param_types )
        return TEE_ERROR_BAD_PARAMETERS;

    /* Get the key ID from parameters safely */
    res = safe_copy_param_mem( &params[0], &key_id, &key_id_len, MAX_KEY_ID_LENGTH );
    if ( res != TEE_SUCCESS )
        goto exit;

    // Alloc memory for key_data
    key_data_len = AES_KEY_SIZE;
    key_data     = TEE_Malloc( AES_KEY_SIZE, 0 );
    if ( ! key_data )
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    if ( key_data == NULL || key_data_len < AES_KEY_SIZE )
    {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto exit;
    }

    /*
     * Check the object exist and can be dumped into output buffer then dump it.
     */
    res =
        TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, key_id, key_id_len,
                                  TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, &key_obj );
    if ( res != TEE_SUCCESS )
    {
        EMSG( "Failed to open persistent object, res=0x%08x", res );
        goto exit;
    }

    /* Read the key data */
    res = TEE_ReadObjectData( key_obj, key_data, AES_KEY_SIZE, &( uint32_t ){ key_data_len } );
    if ( res != TEE_SUCCESS )
    {
        EMSG( "Failed to read object data, res=0x%08x", res );
        goto exit;
    }

    IMSG( "Key length read: %u\n", key_data_len );

    // Kopiere den Schlüssel in den Ausgabeparameter, wenn er passt
    if ( params[1].memref.size < key_data_len )
    {
        res = TEE_ERROR_SHORT_BUFFER;
        goto exit;
    }

    TEE_MemMove( params[1].memref.buffer, key_data, key_data_len );
    params[1].memref.size = key_data_len;
exit:
    if ( key_id != NULL )
        TEE_Free( (void*)key_id );

    if ( key_data != NULL )
        TEE_Free( key_data );

    if ( key_obj != TEE_HANDLE_NULL )
        TEE_CloseObject( key_obj );

    return res;
}

/*
 * Delete a key from secure storage
 */
static TEE_Result delete_key( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result       res;
    TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
    const char*      key_id;
    size_t           key_id_len;
    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE );

    /* Check parameters */
    if ( param_types != exp_param_types )
        return TEE_ERROR_BAD_PARAMETERS;

    /* Get the key ID from parameters safely */
    res = safe_copy_param_mem( &params[0], &key_id, &key_id_len, MAX_KEY_ID_LENGTH );
    if ( res != TEE_SUCCESS )
        return res;

    /* Open the persistent object for the key */
    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, key_id, key_id_len,
                                    TEE_DATA_FLAG_ACCESS_WRITE_META, &key_obj );
    if ( res != TEE_SUCCESS )
        return res;

    /* Delete the object */
    res = TEE_CloseAndDeletePersistentObject1( key_obj );
    if ( res != TEE_SUCCESS )
    {
        IMSG( "Could not delete persistent object\n" );
    }

    key_obj = TEE_HANDLE_NULL;
    return res;
}

/*
 * Initialize AES-CTR context with the key from secure storage
 */
static TEE_Result init_aes_ctr_context( const char* key_id, size_t key_id_len,
                                        struct aes_ctr_ctx* ctx )
{
    TEE_Result       res;
    TEE_ObjectHandle key_obj       = TEE_HANDLE_NULL;
    TEE_ObjectHandle transient_key = TEE_HANDLE_NULL;
    TEE_Attribute    attr;
    uint8_t          key_data[AES_KEY_SIZE];
    size_t           key_data_len = AES_KEY_SIZE;

    if ( key_id == NULL || key_id_len == 0 || key_id_len > MAX_KEY_ID_LENGTH || ctx == NULL )
        return TEE_ERROR_BAD_PARAMETERS;

    /* Open the persistent object for the key */
    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, key_id, key_id_len,
                                    TEE_DATA_FLAG_ACCESS_READ, &key_obj );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Read the key data */
    res = TEE_ReadObjectData( key_obj, key_data, key_data_len, &( uint32_t ){ key_data_len } );
    if ( res != TEE_SUCCESS || key_data_len != AES_KEY_SIZE )
        goto exit;

    /* Create transient key for crypto operation */
    res = TEE_AllocateTransientObject( TEE_TYPE_AES, AES_KEY_SIZE * 8, &transient_key );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Initialize transient key with the value from secure storage */
    attr.attributeID        = TEE_ATTR_SECRET_VALUE;
    attr.content.ref.buffer = key_data;
    attr.content.ref.length = key_data_len;

    res = TEE_PopulateTransientObject( transient_key, &attr, 1 );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Allocate operation for AES-CTR mode */
    res = TEE_AllocateOperation( &ctx->op, TEE_ALG_AES_CTR, TEE_MODE_ENCRYPT, AES_KEY_SIZE * 8 );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Set the key for the operation */
    res = TEE_SetOperationKey( ctx->op, transient_key );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Generate a random initialization vector */
    TEE_GenerateRandom( ctx->iv, AES_KEY_SIZE );

exit:
    if ( key_obj != TEE_HANDLE_NULL )
        TEE_CloseObject( key_obj );
    if ( transient_key != TEE_HANDLE_NULL )
        TEE_FreeTransientObject( transient_key );

    if ( res != TEE_SUCCESS && ctx->op != TEE_HANDLE_NULL )
    {
        TEE_FreeOperation( ctx->op );
        ctx->op = TEE_HANDLE_NULL;
    }

    return res;
}

/*
 * Free AES-CTR context
 */
static void free_aes_ctr_context( struct aes_ctr_ctx* ctx )
{
    if ( ctx && ctx->op != TEE_HANDLE_NULL )
    {
        TEE_FreeOperation( ctx->op );
        ctx->op = TEE_HANDLE_NULL;
    }
}

/*
 * Encrypt a file with AES-CTR
 */
static TEE_Result encrypt_file( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result         res;
    struct aes_ctr_ctx ctx    = { .op = TEE_HANDLE_NULL };
    const char*        key_id = NULL;
    size_t             key_id_len;
    const char*        in_data = NULL;
    size_t             in_len;
    uint8_t*           out_data = NULL;
    size_t             out_len;
    uint32_t           exp_param_types =
        TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                         TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT );

    /* Check parameters */
    if ( param_types != exp_param_types )
        return TEE_ERROR_BAD_PARAMETERS;

    /* Get the key ID from parameters safely */
    res = safe_copy_param_mem( &params[0], &key_id, &key_id_len, MAX_KEY_ID_LENGTH );
    if ( res != TEE_SUCCESS )
        return res;

    /* Get the plain text parameters safely */
    res = safe_copy_param_mem( &params[1], &in_data, &in_len, MAX_FILENAME_LENGTH );
    if ( res != TEE_SUCCESS )
    {
        TEE_Free( (void*)key_id );
        return res;
    }

    /* Get parameters */
    out_data = params[2].memref.buffer;
    out_len  = params[2].memref.size;

    if ( out_data == NULL || out_len < in_len + AES_KEY_SIZE )
        return TEE_ERROR_BAD_PARAMETERS;

    /* Initialize AES-CTR context */
    res = init_aes_ctr_context( key_id, key_id_len, &ctx );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* First, copy IV to the beginning of output buffer */
    memcpy( out_data, ctx.iv, AES_KEY_SIZE );

    /* Initialize the encryption operation */
    TEE_CipherInit( ctx.op, ctx.iv, AES_KEY_SIZE );

    /* Encrypt the data */
    uint32_t actual_out_len = out_len - AES_KEY_SIZE;
    res = TEE_CipherDoFinal( ctx.op, in_data, in_len, out_data + AES_KEY_SIZE, &actual_out_len );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Set the actual output size (IV + encrypted data) */
    params[3].value.a = actual_out_len + AES_KEY_SIZE;

exit:
    free_aes_ctr_context( &ctx );
    return res;
}

/*
 * Decrypt a file with AES-CTR
 */
static TEE_Result decrypt_file( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result          res;
    TEE_OperationHandle op            = TEE_HANDLE_NULL;
    TEE_ObjectHandle    key_obj       = TEE_HANDLE_NULL;
    TEE_ObjectHandle    transient_key = TEE_HANDLE_NULL;
    TEE_Attribute       attr;
    const char*         key_id = NULL;
    size_t              key_id_len;
    const char*         in_data = NULL;
    size_t              in_len;
    uint8_t*            out_data = NULL;
    size_t              out_len;
    uint8_t             key_data[AES_KEY_SIZE];
    size_t              key_data_len = AES_KEY_SIZE;
    uint8_t             iv[AES_KEY_SIZE];
    uint32_t            exp_param_types =
        TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                         TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT );

    /* Check parameters */
    if ( param_types != exp_param_types )
        return TEE_ERROR_BAD_PARAMETERS;

    /* Get the key ID from parameters safely */
    res = safe_copy_param_mem( &params[0], &key_id, &key_id_len, MAX_KEY_ID_LENGTH );
    if ( res != TEE_SUCCESS )
        return res;

    /* Get the encrypted text parameters safely */
    res = safe_copy_param_mem( &params[1], &in_data, &in_len, MAX_FILENAME_LENGTH );
    if ( res != TEE_SUCCESS )
    {
        TEE_Free( (void*)key_id );
        return res;
    }

    /* Get parameters */
    out_data = params[2].memref.buffer;
    out_len  = params[2].memref.size;

    if ( out_data == NULL || out_len < in_len - AES_KEY_SIZE )
        return TEE_ERROR_BAD_PARAMETERS;

    /* Open the persistent object for the key */
    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, key_id, key_id_len,
                                    TEE_DATA_FLAG_ACCESS_READ, &key_obj );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Read the key data */
    res = TEE_ReadObjectData( key_obj, key_data, key_data_len, &( uint32_t ){ key_data_len } );
    if ( res != TEE_SUCCESS || key_data_len != AES_KEY_SIZE )
        goto exit;

    /* Create transient key for crypto operation */
    res = TEE_AllocateTransientObject( TEE_TYPE_AES, AES_KEY_SIZE * 8, &transient_key );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Initialize transient key with the value from secure storage */
    attr.attributeID        = TEE_ATTR_SECRET_VALUE;
    attr.content.ref.buffer = key_data;
    attr.content.ref.length = key_data_len;

    res = TEE_PopulateTransientObject( transient_key, &attr, 1 );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Allocate operation for AES-CTR mode */
    res = TEE_AllocateOperation( &op, TEE_ALG_AES_CTR, TEE_MODE_DECRYPT, AES_KEY_SIZE * 8 );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Set the key for the operation */
    res = TEE_SetOperationKey( op, transient_key );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Extract IV from the beginning of input data */
    memcpy( iv, in_data, AES_KEY_SIZE );

    /* Initialize the decryption operation */
    TEE_CipherInit( op, iv, AES_KEY_SIZE );

    /* Decrypt the data (skipping the IV) */
    uint32_t actual_out_len = out_len;
    res = TEE_CipherDoFinal( op, in_data + AES_KEY_SIZE, in_len - AES_KEY_SIZE, out_data,
                             &actual_out_len );
    if ( res != TEE_SUCCESS )
        goto exit;

    /* Set the actual output size */
    params[3].value.a = actual_out_len;

exit:
    if ( op != TEE_HANDLE_NULL )
        TEE_FreeOperation( op );
    if ( key_obj != TEE_HANDLE_NULL )
        TEE_CloseObject( key_obj );
    if ( transient_key != TEE_HANDLE_NULL )
        TEE_FreeTransientObject( transient_key );

    return res;
}

/*
 * Called when the instance of the TA is created. This is the first call in the TA.
 */
TEE_Result TA_CreateEntryPoint( void )
{
    DMSG( "has been called" );
    return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or called TEE_Panic. This is the last call in the TA.
 */
void TA_DestroyEntryPoint( void )
{
    DMSG( "has been called" ); /* Nothing to do */
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the TA.
 */
TEE_Result TA_OpenSessionEntryPoint( uint32_t param_types, TEE_Param __maybe_unused params[4],
                                     void __maybe_unused** sess_ctx )
{
    DMSG( "has been called" );
    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE );
    if ( param_types != exp_param_types )
        return TEE_ERROR_BAD_PARAMETERS;

    /* Nothing to do here */
    return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint( void __maybe_unused* sess_ctx )
{
    /* Nothing to do here */
    IMSG( "Goodbye!\n" );
}

/*
 * Called when a command is invoked.
 */
TEE_Result TA_InvokeCommandEntryPoint( void __maybe_unused* sess_ctx, uint32_t cmd_id,
                                       uint32_t param_types, TEE_Param params[4] )
{
    switch ( cmd_id )
    {
    case TA_AES_CMD_GENERATE_KEY:
        return generate_and_store_key( param_types, params );
    case TA_AES_CMD_SET_KEY:
        return set_key( param_types, params );
    case TA_AES_CMD_GET_KEY:
        return get_key( param_types, params );
    case TA_AES_CMD_DELETE_KEY:
        return delete_key( param_types, params );
    case TA_AES_CMD_ENCRYPT_FILE:
        return encrypt_file( param_types, params );
    case TA_AES_CMD_DECRYPT_FILE:
        return decrypt_file( param_types, params );
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}