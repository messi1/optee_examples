#pragma once
#include "AesFileEncryptor.h"
#include "KeyManager.h"
#include <string>

class AesSecureStorageFacade {
public:
  AesSecureStorageFacade();

  void generateKey(const std::string &key_id);
  void setKey(const std::string &key_id, const std::string &hex_key);
  std::string getKey(const std::string &key_id);
  void deleteKey(const std::string &key_id);
  void encryptFile(const std::string &key_id, const std::string &in_file,
                   const std::string &out_file);
  void decryptFile(const std::string &key_id, const std::string &in_file,
                   const std::string &out_file);

private:
  OpTeeContextManager ctx_;
  KeyManager key_mgr_;
  AesFileEncryptor file_crypto_;
};
