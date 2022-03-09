cmake_minimum_required(VERSION 3.23)

set(CMAKE_C_STANDARD 99)

# For "CMAKE_INSTALL_<dir>" standard installation directories
include(GNUInstallDirs)

project(hmac_sha256 LANGUAGES C CXX)

option(HMAC_SHA256_TESTS "Build unit tests" FALSE)
option(HMAC_SHA256_EXAMPLES "Build the examples" FALSE)

add_library(hmac_sha256 STATIC)
target_sources(hmac_sha256
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/sha256.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hmac_sha256.c
  PUBLIC FILE_SET HEADERS FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/sha256.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hmac_sha256.h
)

install(TARGETS hmac_sha256
  LIBRARY DESTINATION           "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION           "${CMAKE_INSTALL_LIBDIR}"
  FILE_SET HEADERS DESTINATION  "${CMAKE_INSTALL_INCLUDEDIR}"
)

if (HMAC_SHA256_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(HMAC_SHA256_EXAMPLES)
  add_subdirectory(examples)
endif()
