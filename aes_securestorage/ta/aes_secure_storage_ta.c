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
#include <tee_api.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "asymmetric_key_ops.h"
#include "symmetric_key_ops.h"

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
    switch ( (enum AesSecureStorageTaCmd)cmd_id )
    {
    case AES_SECURE_STORAGE_CMD_GENERATE_KEY:
        return generateKey( param_types, params );
    case AES_SECURE_STORAGE_CMD_DELETE_KEY:
        return deleteKey( param_types, params );
    case AES_SECURE_STORAGE_CMD_ENCRYPT_BUFFER:
        return encryptBuffer( param_types, params );
    case AES_SECURE_STORAGE_CMD_DECRYPT_BUFFER:
        return decryptBuffer( param_types, params );
    case AES_SECURE_STORAGE_CMD_GENERATE_ASYMMETRIC_KEYPAIR:
        return generateAsymmetricKeyPair( param_types, params );
    case AES_SECURE_STORAGE_CMD_GET_PUBLIC_KEY:
        return getPublicKey( param_types, params );
    case AES_SECURE_STORAGE_CMD_DELETE_ASYMMETRIC_KEYPAIR:
        return deleteAsymmetricKeyPair( param_types, params );
    case AES_SECURE_STORAGE_CMD_ASYMMETRIC_DECRYPT:
        return asymmetricDecrypt( param_types, params );
    case AES_SECURE_STORAGE_CMD_KEY_AGREEMENT:
        return keyAgreement( param_types, params );
    case AES_SECURE_STORAGE_CMD_SIGN_DATA:
        return signData( param_types, params );
    case AES_SECURE_STORAGE_CMD_VERIFY_SIGNATURE:
        return verifySignature( param_types, params );
    case AES_SECURE_STORAGE_CMD_GENERATE_CSR:
        return generateCSR( param_types, params );
    case AES_SECURE_STORAGE_CMD_VALIDATE_CERTIFICATE:
        return validateCertificate( param_types, params );
    case AES_SECURE_STORAGE_CMD_STORE_CERTIFICATE:
        return storeCertificate( param_types, params );
    case AES_SECURE_STORAGE_CMD_GET_CERTIFICATE:
        return getCertificate( param_types, params );
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}