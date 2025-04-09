#pragma once
#include "OpTeeContextManager.h"
#include <string>

class KeyManager {
public:
  KeyManager(OpTeeContextManager &ctx);
  void generateKey(const std::string &key_id);
  void setKey(const std::string &key_id, const std::string &hex_key);
  std::string getKey(const std::string &key_id);
  void deleteKey(const std::string &key_id);

private:
  OpTeeContextManager &ctx_;
};