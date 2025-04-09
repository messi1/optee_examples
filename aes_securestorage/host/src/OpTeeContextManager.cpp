#include "OpTeeContextManager.h"
#include <aes_secure_storage_ta.h>
#include <sstream>
#include <stdexcept>
OpTeeContextManager::OpTeeContextManager() {
  TEEC_Result res;
  uint32_t err_origin;

  res = TEEC_InitializeContext(nullptr, &context_);
  if (res != TEEC_SUCCESS) {
    std::stringstream ss;
    ss << "TEEC_InitializeContext failed: 0x" << std::hex << res;
    throw std::runtime_error(ss.str());
  }

  res = TEEC_OpenSession(&context_, &session_, &TA_AES_SECURE_STORAGE_UUID,
                         TEEC_LOGIN_PUBLIC, nullptr, nullptr, &err_origin);
  if (res != TEEC_SUCCESS) {
    std::stringstream ss;
    ss << "TEEC_OpenSession failed: 0x" << std::hex << res << ", origin: 0x"
       << err_origin;
    throw std::runtime_error(ss.str());
  }
}

OpTeeContextManager::~OpTeeContextManager() {
  TEEC_CloseSession(&session_);
  TEEC_FinalizeContext(&context_);
}

TEEC_Session &OpTeeContextManager::getSession() { return session_; }