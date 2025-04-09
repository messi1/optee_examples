#pragma once
#include <span>
#include <string>
#include <vector>

class FileUtils {
public:
  static std::vector<uint8_t> readFile(const std::string &filename);
  static void writeFile(const std::string &filename,
                        std::span<const uint8_t> data);
};
