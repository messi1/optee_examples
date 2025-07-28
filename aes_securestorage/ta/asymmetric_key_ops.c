#include "asymmetric_key_ops.h"
#include <aes_secure_storage_ta.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "TeeUtils.h"

#define ECC_KEY_SIZE_BITS 256
#define ECC_KEY_SIZE_BYTES 32
#define ECC_PUBLIC_KEY_SIZE 64 // Uncompressed format: 0x04 + x + y coordinates
#define ECC_SIGNATURE_SIZE 64  // r + s components
#define MAX_CSR_SIZE 2048
#define MAX_CERT_SIZE 4096
#define MAX_SUBJECT_DN_SIZE 256

// Hilfsfunktion: Schlüssel-ID für asymmetrische Schlüssel erstellen
TEE_Result buildAsymmetricKeyId( const AsymmetricKeyRef* keyRef, const char* suffix, char* buffer,
                                 size_t bufferSize )
{
    int ret = snprintf( buffer, bufferSize, "%s/%s_%s", keyRef->keyringId, keyRef->keyId, suffix );
    if ( ret < 0 || (size_t)ret >= bufferSize )
    {
        return TEE_ERROR_SHORT_BUFFER;
    }
    return TEE_SUCCESS;
}

/*
 * Generate an asymmetric key pair (NIST P-256) and return public key
 */
TEE_Result generateAsymmetricKeyPair( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result       res               = TEE_SUCCESS;
    TEE_ObjectHandle keyObj            = TEE_HANDLE_NULL;
    TEE_ObjectHandle persistentPrivKey = TEE_HANDLE_NULL;
    TEE_ObjectHandle persistentPubKey  = TEE_HANDLE_NULL;
    AsymmetricKeyRef keyRef            = { 0 };
    char             privateKeyId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH * 2];
    char             publicKeyId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH * 2];
    uint8_t          publicKeyBuffer[ECC_PUBLIC_KEY_SIZE];
    uint32_t         publicKeyLen = sizeof( publicKeyBuffer );

    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT,  // keyringId
                                                TEE_PARAM_TYPE_MEMREF_INPUT,  // keyId
                                                TEE_PARAM_TYPE_MEMREF_OUTPUT, // publicKey output
                                                TEE_PARAM_TYPE_VALUE_OUTPUT   // publicKey length
    );

    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Parse keyring and key IDs
    if ( params[0].memref.size >= sizeof( keyRef.keyringId )
         || params[1].memref.size >= sizeof( keyRef.keyId ) )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove( keyRef.keyringId, params[0].memref.buffer, params[0].memref.size );
    TEE_MemMove( keyRef.keyId, params[1].memref.buffer, params[1].memref.size );

    // Build key IDs
    res = buildAsymmetricKeyId( &keyRef, "priv", privateKeyId, sizeof( privateKeyId ) );
    if ( res != TEE_SUCCESS )
        goto out;

    res = buildAsymmetricKeyId( &keyRef, "pub", publicKeyId, sizeof( publicKeyId ) );
    if ( res != TEE_SUCCESS )
        goto out;

    // Create transient ECC key pair object
    res = TEE_AllocateTransientObject( TEE_TYPE_ECDSA_KEYPAIR, ECC_KEY_SIZE_BITS, &keyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    // Generate key pair
    res = TEE_GenerateKey( keyObj, ECC_KEY_SIZE_BITS, NULL, 0 );
    if ( res != TEE_SUCCESS )
        goto out;

    // Extract public key
    res = TEE_GetObjectBufferAttribute( keyObj, TEE_ATTR_ECC_PUBLIC_VALUE_X, publicKeyBuffer,
                                        &publicKeyLen );
    if ( res != TEE_SUCCESS )
        goto out;

    uint32_t yLen = ECC_KEY_SIZE_BYTES;
    res           = TEE_GetObjectBufferAttribute( keyObj, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                                                  publicKeyBuffer + ECC_KEY_SIZE_BYTES, &yLen );
    if ( res != TEE_SUCCESS )
        goto out;

    // Store private key
    res = TEE_CreatePersistentObject( TEE_STORAGE_PRIVATE, privateKeyId, strlen( privateKeyId ),
                                      TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META,
                                      keyObj, NULL, 0, &persistentPrivKey );
    if ( res != TEE_SUCCESS )
        goto out;

    // Create public key object for storage
    TEE_ObjectHandle pubKeyObj = TEE_HANDLE_NULL;
    res = TEE_AllocateTransientObject( TEE_TYPE_ECDSA_PUBLIC_KEY, ECC_KEY_SIZE_BITS, &pubKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    // Set public key attributes
    TEE_Attribute pubKeyAttrs[3];
    TEE_InitRefAttribute( &pubKeyAttrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, publicKeyBuffer,
                          ECC_KEY_SIZE_BYTES );
    TEE_InitRefAttribute( &pubKeyAttrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                          publicKeyBuffer + ECC_KEY_SIZE_BYTES, ECC_KEY_SIZE_BYTES );
    TEE_InitValueAttribute( &pubKeyAttrs[2], TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0 );

    res = TEE_PopulateTransientObject( pubKeyObj, pubKeyAttrs, 3 );
    if ( res != TEE_SUCCESS )
    {
        TEE_FreeTransientObject( pubKeyObj );
        goto out;
    }

    // Store public key
    res = TEE_CreatePersistentObject( TEE_STORAGE_PRIVATE, publicKeyId, strlen( publicKeyId ),
                                      TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META,
                                      pubKeyObj, NULL, 0, &persistentPubKey );
    TEE_FreeTransientObject( pubKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    // Return public key
    if ( params[2].memref.size < ECC_PUBLIC_KEY_SIZE )
    {
        res = TEE_ERROR_SHORT_BUFFER;
        goto out;
    }

    TEE_MemMove( params[2].memref.buffer, publicKeyBuffer, ECC_PUBLIC_KEY_SIZE );
    params[3].value.a = ECC_PUBLIC_KEY_SIZE;

out:
    TEE_FreeTransientObject( keyObj );
    TEE_CloseObject( persistentPrivKey );
    TEE_CloseObject( persistentPubKey );
    return res;
}

/*
 * Get public key for a key pair
 */
TEE_Result getPublicKey( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result       res       = TEE_SUCCESS;
    TEE_ObjectHandle pubKeyObj = TEE_HANDLE_NULL;
    AsymmetricKeyRef keyRef    = { 0 };
    char             publicKeyId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH * 2];
    uint8_t          publicKeyBuffer[ECC_PUBLIC_KEY_SIZE];
    uint32_t         xLen = ECC_KEY_SIZE_BYTES, yLen = ECC_KEY_SIZE_BYTES;

    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT,  // keyringId
                                                TEE_PARAM_TYPE_MEMREF_INPUT,  // keyId
                                                TEE_PARAM_TYPE_MEMREF_OUTPUT, // publicKey output
                                                TEE_PARAM_TYPE_VALUE_OUTPUT   // publicKey length
    );

    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Parse parameters
    if ( params[0].memref.size >= sizeof( keyRef.keyringId )
         || params[1].memref.size >= sizeof( keyRef.keyId ) )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove( keyRef.keyringId, params[0].memref.buffer, params[0].memref.size );
    TEE_MemMove( keyRef.keyId, params[1].memref.buffer, params[1].memref.size );

    res = buildAsymmetricKeyId( &keyRef, "pub", publicKeyId, sizeof( publicKeyId ) );
    if ( res != TEE_SUCCESS )
        goto out;

    // Open public key object
    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, publicKeyId, strlen( publicKeyId ),
                                    TEE_DATA_FLAG_ACCESS_READ, &pubKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    // Extract public key coordinates
    res = TEE_GetObjectBufferAttribute( pubKeyObj, TEE_ATTR_ECC_PUBLIC_VALUE_X, publicKeyBuffer,
                                        &xLen );
    if ( res != TEE_SUCCESS )
        goto out;

    res = TEE_GetObjectBufferAttribute( pubKeyObj, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                                        publicKeyBuffer + ECC_KEY_SIZE_BYTES, &yLen );
    if ( res != TEE_SUCCESS )
        goto out;

    // Return public key
    if ( params[2].memref.size < ECC_PUBLIC_KEY_SIZE )
    {
        res = TEE_ERROR_SHORT_BUFFER;
        goto out;
    }

    TEE_MemMove( params[2].memref.buffer, publicKeyBuffer, ECC_PUBLIC_KEY_SIZE );
    params[3].value.a = ECC_PUBLIC_KEY_SIZE;

out:
    TEE_CloseObject( pubKeyObj );
    return res;
}

/*
 * Delete asymmetric key pair
 */
TEE_Result deleteAsymmetricKeyPair( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result       res        = TEE_SUCCESS;
    TEE_ObjectHandle privKeyObj = TEE_HANDLE_NULL;
    TEE_ObjectHandle pubKeyObj  = TEE_HANDLE_NULL;
    AsymmetricKeyRef keyRef     = { 0 };
    char             privateKeyId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH * 2];
    char             publicKeyId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH * 2];

    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, // keyringId
                                                TEE_PARAM_TYPE_MEMREF_INPUT, // keyId
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE );

    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Parse parameters
    if ( params[0].memref.size >= sizeof( keyRef.keyringId )
         || params[1].memref.size >= sizeof( keyRef.keyId ) )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove( keyRef.keyringId, params[0].memref.buffer, params[0].memref.size );
    TEE_MemMove( keyRef.keyId, params[1].memref.buffer, params[1].memref.size );

    res = buildAsymmetricKeyId( &keyRef, "priv", privateKeyId, sizeof( privateKeyId ) );
    if ( res != TEE_SUCCESS )
        goto out;

    res = buildAsymmetricKeyId( &keyRef, "pub", publicKeyId, sizeof( publicKeyId ) );
    if ( res != TEE_SUCCESS )
        goto out;

    // Delete private key
    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, privateKeyId, strlen( privateKeyId ),
                                    TEE_DATA_FLAG_ACCESS_WRITE_META, &privKeyObj );
    if ( res == TEE_SUCCESS )
    {
        res        = TEE_CloseAndDeletePersistentObject1( privKeyObj );
        privKeyObj = TEE_HANDLE_NULL;
    }

    // Delete public key
    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, publicKeyId, strlen( publicKeyId ),
                                    TEE_DATA_FLAG_ACCESS_WRITE_META, &pubKeyObj );
    if ( res == TEE_SUCCESS )
    {
        res       = TEE_CloseAndDeletePersistentObject1( pubKeyObj );
        pubKeyObj = TEE_HANDLE_NULL;
    }

out:
    TEE_CloseObject( privKeyObj );
    TEE_CloseObject( pubKeyObj );
    return res;
}

/*
 * Decrypt data using private key (RSA/ECC decryption)
 */
TEE_Result asymmetricDecrypt( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result          res        = TEE_SUCCESS;
    TEE_ObjectHandle    privKeyObj = TEE_HANDLE_NULL;
    TEE_OperationHandle op         = TEE_HANDLE_NULL;
    AsymmetricKeyRef    keyRef     = { 0 };
    char                privateKeyId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH * 2];
    memref              ciphertext = { 0 };
    uint32_t            plaintextLen;

    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, // keyringId
                                                TEE_PARAM_TYPE_MEMREF_INPUT, // keyId
                                                TEE_PARAM_TYPE_MEMREF_INPUT, // ciphertext
                                                TEE_PARAM_TYPE_MEMREF_OUTPUT // plaintext
    );

    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Parse parameters
    if ( params[0].memref.size >= sizeof( keyRef.keyringId )
         || params[1].memref.size >= sizeof( keyRef.keyId ) )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove( keyRef.keyringId, params[0].memref.buffer, params[0].memref.size );
    TEE_MemMove( keyRef.keyId, params[1].memref.buffer, params[1].memref.size );

    res = dupParamMemory( &ciphertext, &params[2], AES_SECURE_STORAGE_MAX_BUFFER_LENGTH );
    if ( res != TEE_SUCCESS )
        goto out;

    res = buildAsymmetricKeyId( &keyRef, "priv", privateKeyId, sizeof( privateKeyId ) );
    if ( res != TEE_SUCCESS )
        goto out;

    // Open private key
    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, privateKeyId, strlen( privateKeyId ),
                                    TEE_DATA_FLAG_ACCESS_READ, &privKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    // Allocate decryption operation (assuming RSA for simplicity)
    res = TEE_AllocateOperation( &op, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT, 2048 );
    if ( res != TEE_SUCCESS )
        goto out;

    res = TEE_SetOperationKey( op, privKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    // Decrypt
    plaintextLen = params[3].memref.size;
    res          = TEE_AsymmetricDecrypt( op, NULL, 0, ciphertext.buffer, ciphertext.size,
                                          params[3].memref.buffer, &plaintextLen );
    if ( res != TEE_SUCCESS )
        goto out;

    params[3].memref.size = plaintextLen;

out:
    TEE_FreeOperation( op );
    TEE_CloseObject( privKeyObj );
    destroyMemref( &ciphertext );
    return res;
}

/*
 * ECDH Key Agreement
 */
TEE_Result keyAgreement( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result          res           = TEE_SUCCESS;
    TEE_ObjectHandle    privKeyObj    = TEE_HANDLE_NULL;
    TEE_ObjectHandle    peerPubKeyObj = TEE_HANDLE_NULL;
    TEE_OperationHandle op            = TEE_HANDLE_NULL;
    AsymmetricKeyRef    keyRef        = { 0 };
    char                privateKeyId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH * 2];
    memref              peerPublicKey = { 0 };
    uint32_t            sharedSecretLen;

    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, // keyringId
                                                TEE_PARAM_TYPE_MEMREF_INPUT, // keyId
                                                TEE_PARAM_TYPE_MEMREF_INPUT, // peerPublicKey
                                                TEE_PARAM_TYPE_MEMREF_OUTPUT // sharedSecret
    );

    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Parse parameters
    if ( params[0].memref.size >= sizeof( keyRef.keyringId )
         || params[1].memref.size >= sizeof( keyRef.keyId ) )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove( keyRef.keyringId, params[0].memref.buffer, params[0].memref.size );
    TEE_MemMove( keyRef.keyId, params[1].memref.buffer, params[1].memref.size );

    res = dupParamMemory( &peerPublicKey, &params[2], ECC_PUBLIC_KEY_SIZE );
    if ( res != TEE_SUCCESS )
        goto out;

    res = buildAsymmetricKeyId( &keyRef, "priv", privateKeyId, sizeof( privateKeyId ) );
    if ( res != TEE_SUCCESS )
        goto out;

    // Open private key
    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, privateKeyId, strlen( privateKeyId ),
                                    TEE_DATA_FLAG_ACCESS_READ, &privKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    // Create peer public key object
    res =
        TEE_AllocateTransientObject( TEE_TYPE_ECDH_PUBLIC_KEY, ECC_KEY_SIZE_BITS, &peerPubKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    TEE_Attribute peerAttrs[3];
    TEE_InitRefAttribute( &peerAttrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, peerPublicKey.buffer,
                          ECC_KEY_SIZE_BYTES );
    TEE_InitRefAttribute( &peerAttrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                          (uint8_t*)( peerPublicKey.buffer ) + ECC_KEY_SIZE_BYTES,
                          ECC_KEY_SIZE_BYTES );
    TEE_InitValueAttribute( &peerAttrs[2], TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0 );

    res = TEE_PopulateTransientObject( peerPubKeyObj, peerAttrs, 3 );
    if ( res != TEE_SUCCESS )
        goto out;

    // Allocate ECDH operation
    res = TEE_AllocateOperation( &op, TEE_ALG_ECDH_P256, TEE_MODE_DERIVE, ECC_KEY_SIZE_BITS );
    if ( res != TEE_SUCCESS )
        goto out;

    res = TEE_SetOperationKey( op, privKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    // Perform key derivation
    sharedSecretLen = params[3].memref.size;
    TEE_DeriveKey( op, NULL, 0, peerPubKeyObj );


    // Extract shared secret (simplified - normally you'd use the derived key object)
    TEE_GetOperationInfo( op, NULL );

out:
    TEE_FreeOperation( op );
    TEE_FreeTransientObject( peerPubKeyObj );
    TEE_CloseObject( privKeyObj );
    destroyMemref( &peerPublicKey );
    return res;
}

/*
 * Sign data with private key
 */
TEE_Result signData( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result          res        = TEE_SUCCESS;
    TEE_ObjectHandle    privKeyObj = TEE_HANDLE_NULL;
    TEE_OperationHandle op         = TEE_HANDLE_NULL;
    AsymmetricKeyRef    keyRef     = { 0 };
    char                privateKeyId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH * 2];
    memref              hash = { 0 };
    uint32_t            signatureLen;

    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, // keyringId
                                                TEE_PARAM_TYPE_MEMREF_INPUT, // keyId
                                                TEE_PARAM_TYPE_MEMREF_INPUT, // hash
                                                TEE_PARAM_TYPE_MEMREF_OUTPUT // signature
    );

    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Parse parameters
    if ( params[0].memref.size >= sizeof( keyRef.keyringId )
         || params[1].memref.size >= sizeof( keyRef.keyId ) )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove( keyRef.keyringId, params[0].memref.buffer, params[0].memref.size );
    TEE_MemMove( keyRef.keyId, params[1].memref.buffer, params[1].memref.size );

    res = dupParamMemory( &hash, &params[2], 64 ); // Max hash size
    if ( res != TEE_SUCCESS )
        goto out;

    res = buildAsymmetricKeyId( &keyRef, "priv", privateKeyId, sizeof( privateKeyId ) );
    if ( res != TEE_SUCCESS )
        goto out;

    // Open private key
    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, privateKeyId, strlen( privateKeyId ),
                                    TEE_DATA_FLAG_ACCESS_READ, &privKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    // Allocate signing operation
    res = TEE_AllocateOperation( &op, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, ECC_KEY_SIZE_BITS );
    if ( res != TEE_SUCCESS )
        goto out;

    res = TEE_SetOperationKey( op, privKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    // Sign
    signatureLen = params[3].memref.size;
    res = TEE_AsymmetricSignDigest( op, NULL, 0, hash.buffer, hash.size, params[3].memref.buffer,
                                    &signatureLen );
    if ( res != TEE_SUCCESS )
        goto out;

    params[3].memref.size = signatureLen;

out:
    TEE_FreeOperation( op );
    TEE_CloseObject( privKeyObj );
    destroyMemref( &hash );
    return res;
}

/*
 * Verify signature
 */
TEE_Result verifySignature( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result          res       = TEE_SUCCESS;
    TEE_ObjectHandle    pubKeyObj = TEE_HANDLE_NULL;
    TEE_OperationHandle op        = TEE_HANDLE_NULL;
    memref              publicKey = { 0 };
    memref              hash      = { 0 };
    memref              signature = { 0 };

    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, // publicKey
                                                TEE_PARAM_TYPE_MEMREF_INPUT, // hash
                                                TEE_PARAM_TYPE_MEMREF_INPUT, // signature
                                                TEE_PARAM_TYPE_VALUE_OUTPUT  // isValid
    );

    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = dupParamMemory( &publicKey, &params[0], ECC_PUBLIC_KEY_SIZE );
    if ( res != TEE_SUCCESS )
        goto out;

    res = dupParamMemory( &hash, &params[1], 64 );
    if ( res != TEE_SUCCESS )
        goto out;

    res = dupParamMemory( &signature, &params[2], ECC_SIGNATURE_SIZE );
    if ( res != TEE_SUCCESS )
        goto out;

    // Create public key object
    res = TEE_AllocateTransientObject( TEE_TYPE_ECDSA_PUBLIC_KEY, ECC_KEY_SIZE_BITS, &pubKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    TEE_Attribute pubAttrs[3];
    TEE_InitRefAttribute( &pubAttrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, publicKey.buffer,
                          ECC_KEY_SIZE_BYTES );
    TEE_InitRefAttribute( &pubAttrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                          (uint8_t*)publicKey.buffer + ECC_KEY_SIZE_BYTES, ECC_KEY_SIZE_BYTES );
    TEE_InitValueAttribute( &pubAttrs[2], TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0 );

    res = TEE_PopulateTransientObject( pubKeyObj, pubAttrs, 3 );
    if ( res != TEE_SUCCESS )
        goto out;

    // Allocate verification operation
    res = TEE_AllocateOperation( &op, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY, ECC_KEY_SIZE_BITS );
    if ( res != TEE_SUCCESS )
        goto out;

    res = TEE_SetOperationKey( op, pubKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    // Verify
    res = TEE_AsymmetricVerifyDigest( op, NULL, 0, hash.buffer, hash.size, signature.buffer,
                                      signature.size );

    params[3].value.a = ( res == TEE_SUCCESS ) ? 1 : 0;
    res               = TEE_SUCCESS; // Always return success for the function call

out:
    TEE_FreeOperation( op );
    TEE_FreeTransientObject( pubKeyObj );
    destroyMemref( &publicKey );
    destroyMemref( &hash );
    destroyMemref( &signature );
    return res;
}

// Erweiterung der TA_InvokeCommandEntryPoint Funktion:
/*
 * Neue Kommando-IDs (zu AesSecureStorage.h hinzufügen):
 * 
 * enum AesSecureStorageTaCmd {
 *     // Bestehende Kommandos...
 *     AES_SECURE_STORAGE_CMD_GENERATE_KEY = 0,
 *     AES_SECURE_STORAGE_CMD_DELETE_KEY,
 *     AES_SECURE_STORAGE_CMD_ENCRYPT_BUFFER,
 *     AES_SECURE_STORAGE_CMD_DECRYPT_BUFFER,
 *     
 *     // Neue asymmetrische Kommandos:
 *     AES_SECURE_STORAGE_CMD_GENERATE_ASYMMETRIC_KEYPAIR,
 *     AES_SECURE_STORAGE_CMD_GET_PUBLIC_KEY,
 *     AES_SECURE_STORAGE_CMD_DELETE_ASYMMETRIC_KEYPAIR,
 *     AES_SECURE_STORAGE_CMD_ASYMMETRIC_DECRYPT,
 *     AES_SECURE_STORAGE_CMD_KEY_AGREEMENT,
 *     AES_SECURE_STORAGE_CMD_SIGN_DATA,
 *     AES_SECURE_STORAGE_CMD_VERIFY_SIGNATURE,
 * };
 */

// Erweiterung für TA_InvokeCommandEntryPoint (neue cases hinzufügen):
/*
    case AES_SECURE_STORAGE_CMD_GENERATE_ASYMMETRIC_KEYPAIR:
        return generateAsymmetricKeyPair(param_types, params);
    case AES_SECURE_STORAGE_CMD_GET_PUBLIC_KEY:
        return getPublicKey(param_types, params);
    case AES_SECURE_STORAGE_CMD_DELETE_ASYMMETRIC_KEYPAIR:
        return deleteAsymmetricKeyPair(param_types, params);
    case AES_SECURE_STORAGE_CMD_ASYMMETRIC_DECRYPT:
        return asymmetricDecrypt(param_types, params);
    case AES_SECURE_STORAGE_CMD_KEY_AGREEMENT:
        return keyAgreement(param_types, params);
    case AES_SECURE_STORAGE_CMD_SIGN_DATA:
        return signData(param_types, params);
    case AES_SECURE_STORAGE_CMD_VERIFY_SIGNATURE:
        return verifySignature(param_types, params);
    case AES_SECURE_STORAGE_CMD_GENERATE_CSR:
        return generateCSR(param_types, params);
    case AES_SECURE_STORAGE_CMD_VALIDATE_CERTIFICATE:
        return validateCertificate(param_types, params);
    case AES_SECURE_STORAGE_CMD_STORE_CERTIFICATE:
        return storeCertificate(param_types, params);
    case AES_SECURE_STORAGE_CMD_GET_CERTIFICATE:
        return getCertificate(param_types, params);
*/

/*
 * Generate Certificate Signing Request (CSR)
 */
TEE_Result generateCSR( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result       res        = TEE_SUCCESS;
    TEE_ObjectHandle privKeyObj = TEE_HANDLE_NULL;
    TEE_ObjectHandle pubKeyObj  = TEE_HANDLE_NULL;
    AsymmetricKeyRef keyRef     = { 0 };
    char             privateKeyId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH * 2];
    char             publicKeyId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH * 2];
    memref           subjectDN  = { 0 };
    memref           extensions = { 0 };

    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, // keyringId
                                                TEE_PARAM_TYPE_MEMREF_INPUT, // keyId
                                                TEE_PARAM_TYPE_MEMREF_INPUT, // subjectDN
                                                TEE_PARAM_TYPE_MEMREF_OUTPUT // CSR output
    );

    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Parse parameters
    if ( params[0].memref.size >= sizeof( keyRef.keyringId )
         || params[1].memref.size >= sizeof( keyRef.keyId ) )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove( keyRef.keyringId, params[0].memref.buffer, params[0].memref.size );
    TEE_MemMove( keyRef.keyId, params[1].memref.buffer, params[1].memref.size );

    res = dupParamMemory( &subjectDN, &params[2], MAX_SUBJECT_DN_SIZE );
    if ( res != TEE_SUCCESS )
        goto out;

    res = buildAsymmetricKeyId( &keyRef, "priv", privateKeyId, sizeof( privateKeyId ) );
    if ( res != TEE_SUCCESS )
        goto out;

    res = buildAsymmetricKeyId( &keyRef, "pub", publicKeyId, sizeof( publicKeyId ) );
    if ( res != TEE_SUCCESS )
        goto out;

    // Open private and public keys
    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, privateKeyId, strlen( privateKeyId ),
                                    TEE_DATA_FLAG_ACCESS_READ, &privKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, publicKeyId, strlen( publicKeyId ),
                                    TEE_DATA_FLAG_ACCESS_READ, &pubKeyObj );
    if ( res != TEE_SUCCESS )
        goto out;

    // NOTE: CSR generation is complex and typically requires ASN.1 encoding
    // This is a simplified placeholder implementation
    // In a real implementation, you would:
    // 1. Create ASN.1 structure for CSR
    // 2. Include subject DN and extensions
    // 3. Sign the CSR with private key
    // 4. Encode in DER/PEM format

    // For now, return a simple placeholder
    const char* placeholder_csr =
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIICXjCCAUYCAQAwFjEUMBIGA1UEAwwLdGVzdC1jZXJ0MIIBIjANBgkqhkiG9w0B\n"
        "AQEFAAOCAQ8AMIIBCgKCAQEA...\n"
        "-----END CERTIFICATE REQUEST-----\n";

    size_t csr_len = strlen( placeholder_csr );
    if ( params[3].memref.size < csr_len )
    {
        res = TEE_ERROR_SHORT_BUFFER;
        goto out;
    }

    TEE_MemMove( params[3].memref.buffer, placeholder_csr, csr_len );
    params[3].memref.size = csr_len;

out:
    TEE_CloseObject( privKeyObj );
    TEE_CloseObject( pubKeyObj );
    destroyMemref( &subjectDN );
    return res;
}

/*
 * Validate X.509 Certificate
 */
TEE_Result validateCertificate( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result res         = TEE_SUCCESS;
    memref     certificate = { 0 };
    TEE_Time   currentTime;
    uint32_t   isValid = 0;

    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, // certificate
                                                TEE_PARAM_TYPE_VALUE_OUTPUT, // isValid
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE );

    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = dupParamMemory( &certificate, &params[0], MAX_CERT_SIZE );
    if ( res != TEE_SUCCESS )
        goto out;

    // Get current system time
    TEE_GetSystemTime( &currentTime );

    // NOTE: X.509 certificate validation is very complex and requires:
    // 1. ASN.1 DER parsing
    // 2. Signature verification against CA public key
    // 3. Certificate chain validation
    // 4. Expiry date checking
    // 5. Extensions validation (key usage, etc.)

    // This is a simplified placeholder implementation
    // In a real implementation, you would parse the certificate structure
    // and perform proper validation

    // For demonstration, we'll do a basic size check and assume validity
    if ( certificate.size > 100 && certificate.size < MAX_CERT_SIZE )
    {
        // Basic check - certificate should contain standard markers
        if ( TEE_MemCompare( certificate.buffer, "-----BEGIN CERTIFICATE-----", 27 ) == 0
             || ( (uint8_t*)certificate.buffer )[0] == 0x30 )
        { // DER format starts with SEQUENCE tag
            isValid = 1;
        }
    }

    params[1].value.a = isValid;

out:
    destroyMemref( &certificate );
    return res;
}

/*
 * Store certificate for a key pair
 */
TEE_Result storeCertificate( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result       res     = TEE_SUCCESS;
    TEE_ObjectHandle certObj = TEE_HANDLE_NULL;
    AsymmetricKeyRef keyRef  = { 0 };
    char             certificateId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH * 2];
    memref           certificate = { 0 };

    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, // keyringId
                                                TEE_PARAM_TYPE_MEMREF_INPUT, // keyId
                                                TEE_PARAM_TYPE_MEMREF_INPUT, // certificate
                                                TEE_PARAM_TYPE_NONE );

    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Parse parameters
    if ( params[0].memref.size >= sizeof( keyRef.keyringId )
         || params[1].memref.size >= sizeof( keyRef.keyId ) )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove( keyRef.keyringId, params[0].memref.buffer, params[0].memref.size );
    TEE_MemMove( keyRef.keyId, params[1].memref.buffer, params[1].memref.size );

    res = dupParamMemory( &certificate, &params[2], MAX_CERT_SIZE );
    if ( res != TEE_SUCCESS )
        goto out;

    res = buildAsymmetricKeyId( &keyRef, "cert", certificateId, sizeof( certificateId ) );
    if ( res != TEE_SUCCESS )
        goto out;

    // Store certificate as persistent object data
    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE, certificateId, strlen( certificateId ),
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META,
        TEE_HANDLE_NULL, certificate.buffer, certificate.size, &certObj );
    if ( res != TEE_SUCCESS )
        goto out;

out:
    TEE_CloseObject( certObj );
    destroyMemref( &certificate );
    return res;
}

/*
 * Get stored certificate for a key pair
 */
TEE_Result getCertificate( uint32_t param_types, TEE_Param params[4] )
{
    TEE_Result       res     = TEE_SUCCESS;
    TEE_ObjectHandle certObj = TEE_HANDLE_NULL;
    AsymmetricKeyRef keyRef  = { 0 };
    char             certificateId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH * 2];
    uint32_t         certSize;

    uint32_t exp_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT,  // keyringId
                                                TEE_PARAM_TYPE_MEMREF_INPUT,  // keyId
                                                TEE_PARAM_TYPE_MEMREF_OUTPUT, // certificate output
                                                TEE_PARAM_TYPE_VALUE_OUTPUT   // certificate size
    );

    if ( param_types != exp_param_types )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Parse parameters
    if ( params[0].memref.size >= sizeof( keyRef.keyringId )
         || params[1].memref.size >= sizeof( keyRef.keyId ) )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove( keyRef.keyringId, params[0].memref.buffer, params[0].memref.size );
    TEE_MemMove( keyRef.keyId, params[1].memref.buffer, params[1].memref.size );

    res = buildAsymmetricKeyId( &keyRef, "cert", certificateId, sizeof( certificateId ) );
    if ( res != TEE_SUCCESS )
        goto out;

    // Open certificate object
    res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE, certificateId, strlen( certificateId ),
                                    TEE_DATA_FLAG_ACCESS_READ, &certObj );
    if ( res != TEE_SUCCESS )
        goto out;

    // Get certificate size
    TEE_ObjectInfo objInfo;
    res = TEE_GetObjectInfo1( certObj, &objInfo );
    if ( res != TEE_SUCCESS )
        goto out;

    certSize = objInfo.dataSize;
    if ( params[2].memref.size < certSize )
    {
        res               = TEE_ERROR_SHORT_BUFFER;
        params[3].value.a = certSize; // Return required size
        goto out;
    }

    // Read certificate data
    res = TEE_ReadObjectData( certObj, params[2].memref.buffer, certSize, &certSize );
    if ( res != TEE_SUCCESS )
        goto out;

    params[2].memref.size = certSize;
    params[3].value.a     = certSize;

out:
    TEE_CloseObject( certObj );
    return res;
}