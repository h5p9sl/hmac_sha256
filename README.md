# [hmac_sha256](https://github.com/h5p9sl/hmac_sha256)
A SHA256 HMAC implementation in C/C++

## Example (C++)
```cpp
#include "hmac_sha256.h"

#include <iostream>
#include <sstream>
#include <cstdlib>
#include <cstring>

int main(void) {
    static const char* testvector = "b0344c61d8db38535ca8afceafbf12b881dc20c9833da726e9376c2e32cff7";
    uint8_t* key, *data, *out;
    unsigned keylen, datalen, outlen;
    std::stringstream result;

    // Allocate memory
    keylen = 20;
    datalen = 8;
    outlen = 32;
    key = (uint8_t*)malloc(keylen);
    data = (uint8_t*)malloc(datalen);
    out = (uint8_t*)malloc(outlen);

    // Initialize variables
    strncpy((char*)data, "Hi There", datalen);
    memset(key, 0x0b, 20);

    hmac_sha256(key, keylen, data, datalen, out, outlen);

    // Convert 'out' to string
    for (unsigned i = 0; i < outlen; i++) {
        result << std::hex << (int)out[i];
    }
    std::cout << result.str() << std::endl;
    std::cout << testvector << std::endl;

    // Compare result
    if (strncmp(testvector, result.str().c_str(), result.str().length()) == 0) {
        std::cout << "Test passed!" << std::endl;
    } else {
        std::cout << "Test failed." << std::endl;
    }

    return 0;
}
```
