/*
 * Copyright (c) 2016, Linaro Limited
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

#include <iostream>
#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <AesSecureStorageFacade.h>
#include <OpTeeException.h>

/**
 * @brief Display program usage
 */
void printUsage( const char* progName )
{
    std::cerr << "Verwendung:\n"
              << "  " << progName << " wipe_secure_storage\n"
              << "  " << progName << " create_keyring <keyring_id>\n"
              << "  " << progName << " delete_keyring <keyring_id>\n"
              << "  " << progName << " keyring_exists <keyring_id>\n"
              << "  " << progName << " add_secret <keyring_id> <key_id> <secret>\n"
              << "  " << progName << " get_secret <keyring_id> <key_id>\n"
              << "  " << progName << " update_secret <keyring_id> <key_id> <secret>\n"
              << "  " << progName << " delete_secret <keyring_id> <key_id>\n"
              << "  " << progName << " list_secrets\n"
              << "\n"
              << "Examples:\n"
              << "  " << progName << " wipe_secure_storage\n"
              << "  " << progName << " create_keyring my_ring\n"
              << "  " << progName << " add_secret my_ring my_key geheim\n"
              << "  " << progName << " get_secret my_ring my_key\n"
              << "  " << progName << " update_secret my_ring my_key geheim_v2\n"
              << "  " << progName << " delete_secret my_ring my_key\n"
              << "  " << progName << " delete_keyring my_ring\n"
              << "  " << progName << " keyring_exists my_ring\n"
              << "  " << progName << " list_secrets\n";
    std::exit( 1 );
}

void displayUsage()
{
    std::cerr << "Usage:\n"
                 "  optee_example_aes_securestorage genkey <key_id>\n"
                 "  optee_example_aes_securestorage setkey <key_id> <hex_key>\n"
                 "  optee_example_aes_securestorage getkey <key_id>\n"
                 "  optee_example_aes_securestorage delkey <key_id>\n"
                 "  optee_example_aes_securestorage encrypt <key_id> <input_file> "
                 "<output_file>\n"
                 "  optee_example_aes_securestorage decrypt <key_id> <input_file> "
                 "<output_file>\n"
                 "\n"
                 "Examples:\n"
                 "  optee_example_aes_securestorage genkey key1\n"
                 "  optee_example_aes_securestorage setkey key1 "
                 "00112233445566778899AABBCCDDEEFF\n"
                 "  optee_example_aes_securestorage getkey key1\n"
                 "  optee_example_aes_securestorage delkey key1\n"
                 "  optee_example_aes_securestorage encrypt key1 plain.txt cipher.bin\n"
                 "  optee_example_aes_securestorage decrypt key1 cipher.bin "
                 "decrypted.txt\n";
    std::exit( 1 );
}

int main( int argc, char* argv[] )
{
    try
    {
        if ( argc < 2 )
        {
            printUsage( argv[0] );
            return 1;
        }

        AesSecureStorageFacade storage;
        std::string            cmd = argv[1];

        if ( cmd == "wipe_secure_storage" )
        {
            std::cout << ( storage.wipeSecureStorage() ? "Success" : "Failed" ) << std::endl;
        }
        else if ( cmd == "create_keyring" && argc == 3 )
        {
            std::cout << ( storage.createKeyring( argv[2] ) ? "Keyring created"
                                                            : "Failed to create keyring" )
                      << std::endl;
        }
        else if ( cmd == "delete_keyring" && argc == 3 )
        {
            std::cout << ( storage.deleteKeyring( argv[2] ) ? "Keyring deleted"
                                                            : "Failed to delete keyring" )
                      << std::endl;
        }
        else if ( cmd == "keyring_exists" && argc == 3 )
        {
            std::cout << ( storage.keyringExists( argv[2] ) ? "Keyring exists"
                                                            : "Keyring does not exist" )
                      << std::endl;
        }
        else if ( cmd == "add_secret" && argc == 5 )
        {
            ByteArray secret( argv[4], argv[4] + strlen( argv[4] ) );
            std::cout << ( storage.addSecret( argv[2], argv[3], secret ) ? "Secret added"
                                                                         : "Failed to add secret" )
                      << std::endl;
        }
        else if ( cmd == "get_secret" && argc == 4 )
        {
            try
            {
                std::string secret = storage.getSecret( argv[2], argv[3] );
                std::cout << "Secret: " << secret << std::endl;
            }
            catch ( const std::exception& e )
            {
                std::cerr << "Error retrieving secret: " << e.what() << std::endl;
            }
        }
        else if ( cmd == "update_secret" && argc == 5 )
        {
            ByteArray secret( argv[4], argv[4] + strlen( argv[4] ) );
            std::cout << ( storage.updateSecret( argv[2], argv[3], secret )
                               ? "Secret updated"
                               : "Failed to update secret" )
                      << std::endl;
        }
        else if ( cmd == "delete_secret" && argc == 4 )
        {
            std::cout << ( storage.deleteSecret( argv[2], argv[3] ) ? "Secret deleted"
                                                                    : "Failed to delete secret" )
                      << std::endl;
        }
        else if ( cmd == "list_secrets" )
        {
            std::vector<std::string> ids = storage.listSecretIds();
            for ( const auto& id : ids )
            {
                std::cout << id << std::endl;
            }
        }
        else
        {
            std::cerr << "Unknown or invalid command.\n";
            printUsage( argv[0] );
            return 1;
        }
    }
    catch ( const OpTeeException& e )
    {
        std::cerr << "OP-TEE Error: " << e.what() << "\n";
        return 1;
    }
    catch ( const std::exception& e )
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
