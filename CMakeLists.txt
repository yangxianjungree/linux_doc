cmake_minimum_required(VERSION 3.17)
project(SYSTEMCALL C)

set(CMAKE_C_STANDARD 11)

add_subdirectory(system_call_with_libc)
add_subdirectory(system_call_without_libc)