#pragma once
#include <string>
#include "AesFileEncryptor.h"
#include "KeyManager.h"

class AesSecureStorageFacade
{
public:
    AesSecureStorageFacade();
    bool wipeSecureStorage();
    bool createKeyring( std::string_view keyringId );
    bool deleteKeyring( std::string_view keyringId );
    bool keyringExists( std::string_view keyringId ) const;
    bool addSecret( std::string_view keyringId, std::string_view keyId, const ByteArray& secret );
    std::string              getSecret( std::string_view keyringId, std::string_view keyId );
    bool                     updateSecret( std::string_view keyringId, std::string_view keyId,
                                           const ByteArray& secret );
    bool                     deleteSecret( std::string_view keyringId, std::string_view keyId );
    std::vector<std::string> listSecretIds() const;

private:
    OpTeeContextManager ctx_;
    KeyManager          key_mgr_;
    AesFileEncryptor    file_crypto_;
};
