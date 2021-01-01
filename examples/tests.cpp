#include "../hmac_sha256.h"

#include <cassert>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#define SHA256_HASH_SIZE 32

typedef std::vector<std::tuple<std::string, std::string, std::string>> TestData_t;

void do_tests(const TestData_t& test_vectors) {
    // Perform tests
    for (auto tvec : test_vectors) {
        std::stringstream ss_result;
        std::vector<uint8_t> out(SHA256_HASH_SIZE);
        hmac_sha256(
            std::get<0>(tvec).data(), std::get<0>(tvec).size(),
            std::get<1>(tvec).data(), std::get<1>(tvec).size(),
            out.data(),  out.size()
        );
        for (uint8_t i : out) { ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)i; }
        if (std::get<2>(tvec) != ss_result.str()) {
            std::cout << "TEST FAILED: \n\t" << ss_result.str() << " != \n\t" << std::get<2>(tvec) << std::endl;
        } else {
            std::cout << "Test successful" << std::endl;
        }
    }
}

int main() {
    const TestData_t test_vectors = {
        // Key      Data      HMAC
        {
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
            "Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        }, {
            "Jefe",
            "what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        }, {
            "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
            "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        }, {
            "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
            "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd",
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        },
    };
    do_tests(test_vectors);
    return 0;
}

