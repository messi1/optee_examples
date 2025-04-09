#include "KeyManager.h"
#include <array>
#include <iostream>
#include <stdexcept>
#include "HexConverter.h"

KeyManager::KeyManager( OpTeeContextManager& ctx )
    : ctx_( ctx )
{
}

void KeyManager::generateKey( const std::string& key_id )
{
    TEEC_Operation op{};
    op.paramTypes = TEEC_PARAM_TYPES( TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE );
    op.params[0].tmpref.buffer = const_cast<char*>( key_id.c_str() );
    op.params[0].tmpref.size   = key_id.size() + 1;

    auto res = TEEC_InvokeCommand( &ctx_.getSession(), 0, &op, nullptr );
    if ( res != TEEC_SUCCESS )
        throw std::runtime_error( "Failed to generate key" );
    std::cout << "Key was successfully generated and stored\n";
}

void KeyManager::setKey( const std::string& key_id, const std::string& hex_key )
{
    auto key = HexConverter::hexToBinary( hex_key );

    TEEC_Operation op{};
    op.paramTypes =
        TEEC_PARAM_TYPES( TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE );
    op.params[0].tmpref.buffer = const_cast<char*>( key_id.c_str() );
    op.params[0].tmpref.size   = key_id.size() + 1;
    op.params[1].tmpref.buffer = key.data();
    op.params[1].tmpref.size   = key.size();

    auto res = TEEC_InvokeCommand( &ctx_.getSession(), 1, &op, nullptr );
    if ( res != TEEC_SUCCESS )
        throw std::runtime_error( "Failed to set key" );

    std::cout << "Key was successfully stored\n";
}

std::string KeyManager::getKey( const std::string& key_id )
{
    std::array<uint8_t, 16> key{};

    TEEC_Operation op{};
    op.paramTypes =
        TEEC_PARAM_TYPES( TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE );
    op.params[0].tmpref.buffer = const_cast<char*>( key_id.c_str() );
    op.params[0].tmpref.size   = key_id.size() + 1;
    op.params[1].tmpref.buffer = key.data();
    op.params[1].tmpref.size   = key.size();

    auto res = TEEC_InvokeCommand( &ctx_.getSession(), 2, &op, nullptr );

    if ( res != TEEC_SUCCESS )
        throw std::runtime_error( "Failed to get key" );

    std::cout << "Key was successfully received\n";
    return HexConverter::binaryToHex( key );
}

void KeyManager::deleteKey( const std::string& key_id )
{
    TEEC_Operation op{};
    op.paramTypes = TEEC_PARAM_TYPES( TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE );
    op.params[0].tmpref.buffer = const_cast<char*>( key_id.c_str() );
    op.params[0].tmpref.size   = key_id.size() + 1;

    auto res = TEEC_InvokeCommand( &ctx_.getSession(), 3, &op, nullptr );
    if ( res != TEEC_SUCCESS )
        throw std::runtime_error( "Failed to delete key" );

    std::cout << "Key was successfully deleted\n";
}