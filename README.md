# [hmac_sha256](https://github.com/h5p9sl/hmac_sha256)
A SHA256 HMAC implementation in C/C++

## Usage Example (C++)
```cpp
#include "hmac_sha256.h"

#include <vector>
#include <string>
#include <iostream>
#include <sstream>

#define SHA256_HASHLEN 32

int main() {
    const std::string testvector = "b0344c61d8db38535ca8afceafbf12b881dc20c9833da726e9376c2e32cff7";
    const std::string str_data = "Hi There";

    std::vector<uint8_t> key, data, out;
    std::stringstream result;

    // Allocate memory
    key.resize(20, 0x0b);
    data.resize(str_data.length(), 0);
    out.resize(SHA256_HASHLEN, 0);

    // Fill data
    data.assign(str_data.cbegin(), str_data.cend());

    // Call hmac sha256 function
    hmac_sha256(
        key.data(),  key.size(),
        data.data(), data.size(),
        out.data(),  out.size()
    );

    // Convert 'out' to string
    for (size_t i = 0; i < out.size(); i++) {
        result << std::hex << (int)out[i];
    }
    std::cout << result.str() << std::endl;
    std::cout << testvector << std::endl;

    // Compare result
    if (testvector.compare(result.str()) == 0) {
        std::cout << "Test passed!" << std::endl;
    } else {
        std::cout << "Test failed." << std::endl;
    }

    return 0;
}
```
