#include "../hmac_sha256.h"

#include <cassert>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#define SHA256_HASH_SIZE 32

int main() {
  const std::string str_data = "Hello World!";
  const std::string str_key = "super-secret-key";
  std::stringstream ss_result;

  // Allocate memory for the HMAC
  std::vector<uint8_t> out(SHA256_HASH_SIZE);

  // Call hmac-sha256 function
  hmac_sha256(str_key.data(), str_key.size(), str_data.data(), str_data.size(),
              out.data(), out.size());

  // Convert `out` to string with std::hex
  for (uint8_t x : out) {
    ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
  }

  // Print out the result
  std::cout << "Message: " << str_data << std::endl;
  std::cout << "Key: " << str_key << std::endl;
  std::cout << "HMAC: " << ss_result.str() << std::endl;

  // This assertion fails if something went wrong
  assert(ss_result.str() ==
         "4b393abced1c497f8048860ba1ede46a23f1ff5209b18e9c428bddfbb690aad8");
  return 0;
}
