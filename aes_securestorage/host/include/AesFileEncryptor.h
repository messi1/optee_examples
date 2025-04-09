#pragma once
#include "OpTeeContextManager.h"
#include <string>

class AesFileEncryptor {
public:
  AesFileEncryptor(OpTeeContextManager &ctx);
  void encrypt(const std::string &key_id, const std::string &in_file,
               const std::string &out_file);
  void decrypt(const std::string &key_id, const std::string &in_file,
               const std::string &out_file);

private:
  OpTeeContextManager &ctx_;
};