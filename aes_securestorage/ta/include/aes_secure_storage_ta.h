// Copyright (c) 2025 Franke

#ifndef TA_AES_SECURE_STORAGE_H
#define TA_AES_SECURE_STORAGE_H

/** * @file AesSecureStorage.h
 * @brief Interface for the AES Secure Storage Trusted Application.
 *
 * This file defines the UUID and command IDs for the AES Secure Storage TA.
 * It is used to manage secure storage operations such as key generation,
 * deletion, encryption, and decryption for both symmetric and asymmetric cryptography.
 */

#ifdef __cplusplus
extern "C"
{
#endif

    // Needs to be the same as in the Makefile
#define AES_SECURE_STORAGE_TA_UUID                                                                 \
    {                                                                                              \
        0x5dbac793, 0xf574, 0x4871,                                                                \
        {                                                                                          \
            0x8a, 0xd3, 0x04, 0x33, 0x1e, 0xc1, 0x7f, 0x25                                         \
        }                                                                                          \
    }

    /* Command IDs */
    enum AesSecureStorageTaCmd
    {
        /*
         * AES_SECURE_STORAGE_CMD_GENERATE_KEY
         *
         * params
         * [in]   MEMREF key_id : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [NONE]
         * [NONE]
         * [NONE]
         */
        AES_SECURE_STORAGE_CMD_GENERATE_KEY = 0,

        /*
         * AES_SECURE_STORAGE_CMD_DELETE_KEY
         *
         * params
         * [in]   MEMREF key_id : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [NONE]
         * [NONE]
         * [NONE]
         */
        AES_SECURE_STORAGE_CMD_DELETE_KEY = 1,

        /*
         * AES_SECURE_STORAGE_CMD_ENCRYPT_BUFFER
         *
         * params
         * [in]   MEMREF   keyId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF   plainText : char [0..AES_SECURE_STORAGE_MAX_BUFFER_LENGTH]
         * [out]  MEMREF   iv || cipherText : char [len(plainText) + 2 * AES_SECURE_STORAGE_BLOCK_SIZE] (pre-allocated)
         * [out]  VALUE.a  sizeof(iv || cipherText) : uint32_t
         */
        AES_SECURE_STORAGE_CMD_ENCRYPT_BUFFER = 2,

        /*
         * AES_SECURE_STORAGE_CMD_DECRYPT_BUFFER
         *
         * params
         * [in]   MEMREF keyId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF iv || cipherText : char [0..AES_SECURE_STORAGE_MAX_BUFFER_LENGTH]
         * [out]  MEMREF plainText : char [len(iv || cipherText)] (pre-allocated)
         * [out]  VALUE.a  sizeof(plainText) : uint32_t
         */
        AES_SECURE_STORAGE_CMD_DECRYPT_BUFFER = 3,

        /*
         * AES_SECURE_STORAGE_CMD_GENERATE_ASYMMETRIC_KEYPAIR
         *
         * params
         * [in]   MEMREF keyringId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF keyId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [out]  MEMREF publicKey : char [AES_SECURE_STORAGE_MAX_PUBLIC_KEY_SIZE] (pre-allocated)
         * [out]  VALUE.a publicKeySize : uint32_t
         */
        AES_SECURE_STORAGE_CMD_GENERATE_ASYMMETRIC_KEYPAIR = 4,

        /*
         * AES_SECURE_STORAGE_CMD_GET_PUBLIC_KEY
         *
         * params
         * [in]   MEMREF keyringId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF keyId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [out]  MEMREF publicKey : char [AES_SECURE_STORAGE_MAX_PUBLIC_KEY_SIZE] (pre-allocated)
         * [out]  VALUE.a publicKeySize : uint32_t
         */
        AES_SECURE_STORAGE_CMD_GET_PUBLIC_KEY = 5,

        /*
         * AES_SECURE_STORAGE_CMD_DELETE_ASYMMETRIC_KEYPAIR
         *
         * params
         * [in]   MEMREF keyringId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF keyId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [NONE]
         * [NONE]
         */
        AES_SECURE_STORAGE_CMD_DELETE_ASYMMETRIC_KEYPAIR = 6,

        /*
         * AES_SECURE_STORAGE_CMD_ASYMMETRIC_DECRYPT
         *
         * params
         * [in]   MEMREF keyringId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF keyId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF ciphertext : char [0..AES_SECURE_STORAGE_MAX_BUFFER_LENGTH]
         * [out]  MEMREF plaintext : char [AES_SECURE_STORAGE_MAX_BUFFER_LENGTH] (pre-allocated)
         * [out]  VALUE.a plaintextSize : uint32_t
         */
        AES_SECURE_STORAGE_CMD_ASYMMETRIC_DECRYPT = 7,

        /*
         * AES_SECURE_STORAGE_CMD_KEY_AGREEMENT
         *
         * params
         * [in]   MEMREF keyringId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF keyId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF peerPublicKey : char [AES_SECURE_STORAGE_MAX_PUBLIC_KEY_SIZE]
         * [out]  MEMREF sharedSecret : char [AES_SECURE_STORAGE_ECDH_SHARED_SECRET_SIZE] (pre-allocated)
         * [out]  VALUE.a sharedSecretSize : uint32_t
         */
        AES_SECURE_STORAGE_CMD_KEY_AGREEMENT = 8,

        /*
         * AES_SECURE_STORAGE_CMD_SIGN_DATA
         *
         * params
         * [in]   MEMREF keyringId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF keyId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF hash : char [AES_SECURE_STORAGE_HASH_SIZE]
         * [out]  MEMREF signature : char [AES_SECURE_STORAGE_MAX_SIGNATURE_SIZE] (pre-allocated)
         * [out]  VALUE.a signatureSize : uint32_t
         */
        AES_SECURE_STORAGE_CMD_SIGN_DATA = 9,

        /*
         * AES_SECURE_STORAGE_CMD_VERIFY_SIGNATURE
         *
         * params
         * [in]   MEMREF publicKey : char [AES_SECURE_STORAGE_MAX_PUBLIC_KEY_SIZE]
         * [in]   MEMREF hash : char [AES_SECURE_STORAGE_HASH_SIZE]
         * [in]   MEMREF signature : char [AES_SECURE_STORAGE_MAX_SIGNATURE_SIZE]
         * [out]  VALUE.a isValid : uint32_t (1 = valid, 0 = invalid)
         */
        AES_SECURE_STORAGE_CMD_VERIFY_SIGNATURE = 10,

        /*
         * AES_SECURE_STORAGE_CMD_GENERATE_CSR
         *
         * params
         * [in]   MEMREF keyringId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF keyId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF subjectDN : char [AES_SECURE_STORAGE_MAX_DN_LENGTH]
         * [out]  MEMREF csr : char [AES_SECURE_STORAGE_MAX_CSR_SIZE] (pre-allocated)
         * [out]  VALUE.a csrSize : uint32_t
         */
        AES_SECURE_STORAGE_CMD_GENERATE_CSR = 11,

        /*
         * AES_SECURE_STORAGE_CMD_VALIDATE_CERTIFICATE
         *
         * params
         * [in]   MEMREF certificate : char [AES_SECURE_STORAGE_MAX_CERT_SIZE]
         * [out]  VALUE.a isValid : uint32_t (1 = valid, 0 = invalid)
         * [NONE]
         * [NONE]
         */
        AES_SECURE_STORAGE_CMD_VALIDATE_CERTIFICATE = 12,

        /*
         * AES_SECURE_STORAGE_CMD_STORE_CERTIFICATE
         *
         * params
         * [in]   MEMREF keyringId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF keyId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF certificate : char [AES_SECURE_STORAGE_MAX_CERT_SIZE]
         * [NONE]
         */
        AES_SECURE_STORAGE_CMD_STORE_CERTIFICATE = 13,

        /*
         * AES_SECURE_STORAGE_CMD_GET_CERTIFICATE
         *
         * params
         * [in]   MEMREF keyringId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [in]   MEMREF keyId : char [1...AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH]
         * [out]  MEMREF certificate : char [AES_SECURE_STORAGE_MAX_CERT_SIZE] (pre-allocated)
         * [out]  VALUE.a certificateSize : uint32_t
         */
        AES_SECURE_STORAGE_CMD_GET_CERTIFICATE = 14,
    };

    /* AES key size */
#define AES_SECURE_STORAGE_KEY_SIZE 16u /* 128 bits */

    /* AES block size */
#define AES_SECURE_STORAGE_BLOCK_SIZE 16u /* 128 bits */

    /* Maximum key ID length */
#define AES_SECURE_STORAGE_MAX_KEY_ID_LENGTH 64u
#define AES_SECURE_STORAGE_MAX_BUFFER_LENGTH 4096u

    /* Asymmetric crypto sizes for NIST P-256 */
#define AES_SECURE_STORAGE_ECC_KEY_SIZE 32u        /* 256 bits */
#define AES_SECURE_STORAGE_MAX_PUBLIC_KEY_SIZE 65u /* Uncompressed P-256 public key (1 + 32 + 32) */
#define AES_SECURE_STORAGE_MAX_SIGNATURE_SIZE 64u  /* ECDSA signature (r + s) */
#define AES_SECURE_STORAGE_ECDH_SHARED_SECRET_SIZE 32u /* ECDH shared secret size */
#define AES_SECURE_STORAGE_HASH_SIZE 32u               /* SHA-256 hash size */

    /* Certificate and CSR sizes */
#define AES_SECURE_STORAGE_MAX_CSR_SIZE 2048u
#define AES_SECURE_STORAGE_MAX_CERT_SIZE 4096u
#define AES_SECURE_STORAGE_MAX_DN_LENGTH 256u

    /* Storage object types */
#define AES_SECURE_STORAGE_PRIVATE_KEY_SUFFIX "_priv"
#define AES_SECURE_STORAGE_PUBLIC_KEY_SUFFIX "_pub"
#define AES_SECURE_STORAGE_CERTIFICATE_SUFFIX "_cert"

#ifdef __cplusplus
}
#endif

#endif