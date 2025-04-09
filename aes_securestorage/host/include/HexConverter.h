#pragma once
#include <span>
#include <string>
#include <vector>

class HexConverter {
public:
  static std::vector<uint8_t> hexToBinary(const std::string &hex);
  static std::string binaryToHex(std::span<const uint8_t> data);
};
