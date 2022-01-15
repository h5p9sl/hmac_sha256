cmake_minimum_required(VERSION 3.14)

project(hmac-sha256)

add_library(hmac-sha256 STATIC hmac_sha256.c sha256.c )

install(TARGETS hmac-sha256 DESTINATION lib)
install(FILES hmac-sha256.h DESTINATION include)
