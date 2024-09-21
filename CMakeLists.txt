cmake_minimum_required(VERSION 3.15)
project(shattr)
enable_language(ASM)

set(CMAKE_C_FLAGS "--std=gnu99 -O2 -msse4.1 -msha -Wall -Wextra")


#add_definitions()

add_executable(shattr main.c sha256.c sha256-x8664.S)



add_executable(test_sha256 sha256.c sha256-x8664.S)
target_compile_definitions(test_sha256 PUBLIC -DTEST_SHA256_MAIN)
