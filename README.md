# [hmac_sha256](https://github.com/h5p9sl/hmac_sha256)
A SHA256 HMAC implementation in C/C++

## Example (C++)
```cpp
#include "hmac_sha256.h"

#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <tuple>

int main(void) {
    const std::string testvector = "b0344c61d8db38535ca8afceafbf12b881dc20c9833da726e9376c2e32cff7";
	std::vector<uint8_t> key, data, out;
    std::stringstream result;

    // Allocate memory
    key.resize(20);
    data.resize(8);
    out.resize(32);

    // Initialize variables
    strncpy((char*)data.data(), "Hi There", data.size());
    memset(key.data(), 0x0b, key.size());

    // Call hmac sha256 function
    hmac_sha256(key.data(), key.size(),
            data.data(), data.size(),
            out.data(), out.size());

    // Convert 'out' to string
    for (unsigned i = 0; i < out.size(); i++) {
        result << std::hex << (int)out[i];
    }
    std::cout << result.str() << std::endl;
    std::cout << testvector << std::endl;

    // Compare result
    if (testvector.compare(result.str()) == 0) {
        std::cout << "Test passed!" << std::endl;
        return 0;
    }
    std::cout << "Test failed." << std::endl;

    return 0;
}
```
