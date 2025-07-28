#include "AesSecureStorageFacade.h"

AesSecureStorageFacade::AesSecureStorageFacade()
    : key_mgr_( ctx_ )
    , file_crypto_( ctx_ )
{
}

bool AesSecureStorageFacade::wipeSecureStorage()
{
}

bool AesSecureStorageFacade::createKeyring( std::string_view keyringId )
{
}

bool AesSecureStorageFacade::deleteKeyring( std::string_view keyringId )
{
}

bool AesSecureStorageFacade::keyringExists( std::string_view keyringId ) const
{
}

bool AesSecureStorageFacade::addSecret( std::string_view keyringId, std::string_view keyId,
                                        const ByteArray& secret )
{
}

std::string AesSecureStorageFacade::getSecret( std::string_view keyringId, std::string_view keyId )
{
    return key_mgr_.getKey( key_id );
}

bool AesSecureStorageFacade::updateSecret( std::string_view keyringId, std::string_view keyId,
                                           const ByteArray& secret )
{
}

bool AesSecureStorageFacade::deleteSecret( std::string_view keyringId, std::string_view keyId )
{
}

std::vector<std::string> AesSecureStorageFacade::listSecretIds() const
{
}

// void AesSecureStorageFacade::generateKey( const std::string& key_id )
// {
//     key_mgr_.generateKey( key_id );
// }

// void AesSecureStorageFacade::setKey( const std::string& key_id, const std::string& hex_key )
// {
//     key_mgr_.setKey( key_id, hex_key );
// }

// std::string AesSecureStorageFacade::getKey( const std::string& key_id )
// {
//     return key_mgr_.getKey( key_id );
// }

// void AesSecureStorageFacade::deleteKey( const std::string& key_id )
// {
//     key_mgr_.deleteKey( key_id );
// }

// void AesSecureStorageFacade::encryptFile( const std::string& key_id, const std::string& in_file,
//                                           const std::string& out_file )
// {
//     file_crypto_.encrypt( key_id, in_file, out_file );
// }

// void AesSecureStorageFacade::decryptFile( const std::string& key_id, const std::string& in_file,
//                                           const std::string& out_file )
// {
//     file_crypto_.decrypt( key_id, in_file, out_file );
// }