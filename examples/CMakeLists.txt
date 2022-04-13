set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

add_executable(hmac_cxx_example
  hmac_cxx_example.cpp
)

add_executable(hmac_c_example
  hmac_c_example.c
)

target_link_libraries(hmac_cxx_example hmac_sha256)
target_link_libraries(hmac_c_example hmac_sha256)
