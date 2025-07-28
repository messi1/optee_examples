#ifndef ASYMMETRIC_KEY_OPS_H
#define ASYMMETRIC_KEY_OPS_H

#include <tee_internal_api.h>

#define AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH 64u
#define AES_SECURE_STORAGE_MAX_BUFFER_LENGTH 4096u

typedef struct
{
    char keyringId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH];
    char keyId[AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH];
} AsymmetricKeyRef;

/*
 * Generate an asymmetric key pair (NIST P-256) and return public key
 */
TEE_Result generateAsymmetricKeyPair( uint32_t param_types, TEE_Param params[4] );

/*
 * Get public key for a key pair
 */
TEE_Result getPublicKey( uint32_t param_types, TEE_Param params[4] );

/*
 * Delete asymmetric key pair
 */
TEE_Result deleteAsymmetricKeyPair( uint32_t param_types, TEE_Param params[4] );

/*
 * Decrypt data using private key (RSA/ECC decryption)
 */
TEE_Result asymmetricDecrypt( uint32_t param_types, TEE_Param params[4] );

/*
 * ECDH Key Agreement
 */
TEE_Result keyAgreement( uint32_t param_types, TEE_Param params[4] );

/*
 * Sign data with private key
 */
TEE_Result signData( uint32_t param_types, TEE_Param params[4] );

/*
 * Verify signature
 */
TEE_Result verifySignature( uint32_t param_types, TEE_Param params[4] );

/*
 * Generate Certificate Signing Request (CSR)
 */
TEE_Result generateCSR( uint32_t param_types, TEE_Param params[4] );

/*
 * Validate X.509 Certificate
 */
TEE_Result validateCertificate( uint32_t param_types, TEE_Param params[4] );

/*
 * Store certificate for a key pair
 */
TEE_Result storeCertificate( uint32_t param_types, TEE_Param params[4] );

/*
 * Get stored certificate for a key pair
 */
TEE_Result getCertificate( uint32_t param_types, TEE_Param params[4] );

#endif /* ASYMMETRIC_KEY_OPS_H */