/*
    hmac_sha256.h
    Originally written by https://github.com/h5p9sl
*/

#ifndef _HMAC_SHA256_H_
#define _HMAC_SHA256_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stdint.h>

void hmac_sha256(
    // [in]: The key and it's length. Should be at least 32 bytes long for optimal security.
    const void* key, const unsigned keylen,
     // [in]: The data to hash along with the key.
    const void* data, const unsigned datalen,
    // [out]: The output hash. Should be 32 bytes long, but if it's less than 32 bytes, the function will truncate the resulting hash.
    void* out, const unsigned outlen
);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _HMAC_SHA256_H_

