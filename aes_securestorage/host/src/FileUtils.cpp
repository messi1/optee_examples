#include "FileUtils.h"
#include <fstream>
#include <stdexcept>

std::vector<uint8_t> FileUtils::readFile(const std::string &filename) {
  std::ifstream file(filename, std::ios::binary);
  if (!file)
    throw std::runtime_error("Unable to open file for reading: " + filename);
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), {});
}

void FileUtils::writeFile(const std::string &filename,
                          std::span<const uint8_t> data) {
  std::ofstream file(filename, std::ios::binary);
  if (!file)
    throw std::runtime_error("Unable to open file for writing: " + filename);
  file.write(reinterpret_cast<const char *>(data.data()), data.size());
}
