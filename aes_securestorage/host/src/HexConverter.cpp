#include "HexConverter.h"
#include <iomanip>
#include <sstream>
#include <stdexcept>

std::vector<uint8_t> HexConverter::hexToBinary( const std::string& hex )
{
    if ( hex.size() % 2 != 0 )
        throw std::invalid_argument( "Invalid hex string length" );
    std::vector<uint8_t> bin( hex.size() / 2 );
    for ( size_t i = 0; i < bin.size(); ++i )
    {
        std::string byteStr = hex.substr( i * 2, 2 );
        bin[i]              = static_cast<uint8_t>( std::stoi( byteStr, nullptr, 16 ) );
    }
    return bin;
}

std::string HexConverter::binaryToHex( std::span<const uint8_t> data )
{
    std::ostringstream oss;
    for ( auto byte : data )
    {
        oss << std::uppercase << std::hex << std::setw( 2 ) << std::setfill( '0' ) << (int)byte;
    }
    return oss.str();
}
