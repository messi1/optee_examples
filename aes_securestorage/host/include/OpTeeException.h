#pragma once

#include <sstream>
#include <stdexcept>
#include <string>
#include <tee_client_api.h>

/**
 * @brief Exception class for OP-TEE specific errors.
 */
class OpTeeException : public std::runtime_error {
public:
  /**
   * @brief Constructs a new OpTeeException
   *
   * @param msg Error message context
   * @param res TEEC result code
   * @param origin TEEC origin code
   */
  OpTeeException(const std::string &msg, TEEC_Result res, uint32_t origin)
      : std::runtime_error(buildMessage(msg, res, origin)), error_code(res),
        error_origin(origin) {}

  /// TEEC result code
  TEEC_Result error_code;

  /// Origin of the error (TEEC_ORIGIN_* values)
  uint32_t error_origin;

private:
  static std::string buildMessage(const std::string &msg, TEEC_Result res,
                                  uint32_t origin) {
    std::ostringstream oss;
    oss << msg << ". TEEC error: 0x" << std::hex << res << ", origin: 0x"
        << std::hex << origin;
    return oss.str();
  }
};