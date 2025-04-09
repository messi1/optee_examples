#ifndef __AES_SECURE_STORAGE_TA_H__
#define __AES_SECURE_STORAGE_TA_H__

#define TA_AES_SECURE_STORAGE_UUID                                                                 \
    {                                                                                              \
        0x5dbac793, 0xf574, 0x4871,                                                                \
        {                                                                                          \
            0x8a, 0xd3, 0x04, 0x33, 0x1e, 0xc1, 0x7f, 0x25                                         \
        }                                                                                          \
    }

/* Command IDs */
#define TA_AES_CMD_GENERATE_KEY 0
#define TA_AES_CMD_SET_KEY 1
#define TA_AES_CMD_GET_KEY 2
#define TA_AES_CMD_DELETE_KEY 3
#define TA_AES_CMD_ENCRYPT_FILE 4
#define TA_AES_CMD_DECRYPT_FILE 5

/* AES key size */
#define AES_KEY_SIZE 16 /* 128 bits */

/* Maximum key ID length */
#define MAX_KEY_ID_LENGTH 64

#define MAX_FILENAME_LENGTH 4096

#endif /* __AES_SECURE_STORAGE_TA_H__ */
