cmake_minimum_required(VERSION 3.29)
project(C2 C)

set(CMAKE_C_STANDARD 11)

# Set OpenSSL directories
set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_LIBRARIES "${OPENSSL_ROOT_DIR}/lib")

# Specify the OpenSSL include directory
include_directories(${OPENSSL_INCLUDE_DIR})

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Include OpenSSL headers
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(C2
        C2.c
        encrypt_key.c
        encrypt_password.c
        SMC.c
        encrypt_payload.c)

# Link OpenSSL libraries
target_link_libraries(C2 OpenSSL::SSL OpenSSL::Crypto)
