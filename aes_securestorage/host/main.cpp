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
        // Check arguments
        if ( argc < 3 )
        {
            displayUsage();
        }

        // Parse command
        std::string command = argv[1];
        std::string key_id  = argv[2];

        // Initialize client
        AesSecureStorageFacade client;

        // Process command
        if ( command == "genkey" )
        {
            if ( argc != 3 )
                displayUsage();
            client.generateKey( key_id );
        }
        else if ( command == "setkey" )
        {
            if ( argc != 4 )
                displayUsage();
            client.setKey( key_id, argv[3] );
        }
        else if ( command == "getkey" )
        {
            if ( argc != 3 )
                displayUsage();
            auto key = client.getKey( key_id );
            std::cout << "Get key: " << key << "\n";
        }
        else if ( command == "delkey" )
        {
            if ( argc != 3 )
                displayUsage();
            client.deleteKey( key_id );
        }
        else if ( command == "encrypt" )
        {
            if ( argc != 5 )
                displayUsage();
            client.encryptFile( key_id, argv[3], argv[4] );
        }
        else if ( command == "decrypt" )
        {
            if ( argc != 5 )
                displayUsage();
            client.decryptFile( key_id, argv[3], argv[4] );
        }
        else
        {
            displayUsage();
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
