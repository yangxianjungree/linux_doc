set(no_libc_src assm_syscall.S assm_syscall.c)

set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} -nostdlib)

enable_language(C ASM)

add_executable(no_libc ${no_libc_src})