set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

add_executable(tests tests.cpp)
target_link_libraries(tests hmac_sha256)

add_test(hmac_sha256-tests tests)
