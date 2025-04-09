#include "AesFileEncryptor.h"
#include <iostream>
#include <span>
#include <vector>
#include "FileUtils.h"

AesFileEncryptor::AesFileEncryptor( OpTeeContextManager& ctx )
    : ctx_( ctx )
{
}

void AesFileEncryptor::encrypt( const std::string& key_id, const std::string& in_file,
                                const std::string& out_file )
{
    auto                 input = FileUtils::readFile( in_file );
    std::vector<uint8_t> output( input.size() + 16 );

    TEEC_Operation op{};
    op.paramTypes              = TEEC_PARAM_TYPES( TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                                                   TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_OUTPUT );
    op.params[0].tmpref.buffer = const_cast<char*>( key_id.c_str() );
    op.params[0].tmpref.size   = key_id.size() + 1;
    op.params[1].tmpref.buffer = input.data();
    op.params[1].tmpref.size   = input.size();
    op.params[2].tmpref.buffer = output.data();
    op.params[2].tmpref.size   = output.size();

    auto res = TEEC_InvokeCommand( &ctx_.getSession(), 4, &op, nullptr );
    if ( res != TEEC_SUCCESS )
        throw std::runtime_error( "Failed to encrypt file" );

    FileUtils::writeFile( out_file, std::span( output.data(), op.params[3].value.a ) );
}

void AesFileEncryptor::decrypt( const std::string& key_id, const std::string& in_file,
                                const std::string& out_file )
{
    auto                 input = FileUtils::readFile( in_file );
    std::vector<uint8_t> output( input.size() );

    TEEC_Operation op{};
    op.paramTypes              = TEEC_PARAM_TYPES( TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                                                   TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_OUTPUT );
    op.params[0].tmpref.buffer = const_cast<char*>( key_id.c_str() );
    op.params[0].tmpref.size   = key_id.size() + 1;
    op.params[1].tmpref.buffer = input.data();
    op.params[1].tmpref.size   = input.size();
    op.params[2].tmpref.buffer = output.data();
    op.params[2].tmpref.size   = output.size();

    auto res = TEEC_InvokeCommand( &ctx_.getSession(), 5, &op, nullptr );
    if ( res != TEEC_SUCCESS )
        throw std::runtime_error( "Failed to decrypt file" );

    FileUtils::writeFile( out_file, std::span( output.data(), op.params[3].value.a ) );
}