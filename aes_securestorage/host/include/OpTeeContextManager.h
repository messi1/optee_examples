#pragma once
#include <tee_client_api.h>

class OpTeeContextManager {
public:
  OpTeeContextManager();
  ~OpTeeContextManager();
  TEEC_Session &getSession();

private:
  TEEC_Context context_;
  TEEC_Session session_;
};