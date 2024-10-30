cmake_minimum_required(VERSION 3.29)
project(C2 C)

set(CMAKE_C_STANDARD 11)

add_executable(C2
    C2.c
    encrypt_key.c
    encrypt_password.c
    SMC.c)
