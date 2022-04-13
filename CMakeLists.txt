cmake_minimum_required(VERSION 3.14)

set(CMAKE_C_STANDARD 99)

# For "CMAKE_INSTALL_<dir>" standard installation directories
include(GNUInstallDirs)

project(hmac_sha256 LANGUAGES C CXX)

option(HMAC_SHA256_TESTS "Build unit tests" FALSE)
option(HMAC_SHA256_EXAMPLES "Build the examples" FALSE)

add_library(hmac_sha256 STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/sha256.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hmac_sha256.c
)
target_include_directories(hmac_sha256 INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

install(TARGETS hmac_sha256
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)

install(FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/hmac_sha256.h
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

if (HMAC_SHA256_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(HMAC_SHA256_EXAMPLES)
  add_subdirectory(examples)
endif()
