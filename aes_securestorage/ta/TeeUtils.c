// Copyright (c) 2025 Franke

#include "TeeUtils.h"

void destroyMemref( memref* ref )
{
    if ( ref->buffer )
    {
        TEE_Free( ref->buffer );
        ref->buffer = NULL;
        ref->size   = 0;
    }
}

TEE_Result dupParamMemory( memref* dest, const TEE_Param* param, size_t max_size )
{
    /* Validate parameters */
    if ( param == NULL || dest == NULL )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    size_t size = param->memref.size;
    void*  src  = param->memref.buffer;

    /* Validate parameters */
    if ( param->memref.buffer == NULL || param->memref.size == 0 )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Check maximum size if specified */
    if ( max_size > 0 && size > max_size )
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Allocate memory */
    void* dst = TEE_Malloc( size, 0 );
    if ( ! dst )
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* Copy data */
    TEE_MemMove( dst, src, size );

    /* Set output parameters */
    dest->buffer = dst;
    dest->size   = size;


    return TEE_SUCCESS;
}
