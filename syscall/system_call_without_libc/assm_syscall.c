void* my_syscall(
    void* syscall_number,
    void* param1,
    void* param2,
    void* param3,
    void* param4,
    void* param5
);

typedef unsigned long int uintptr; /* size_t */
typedef long int intptr; /* ssize_t */

static
intptr write(int fd, void const* data, uintptr nbytes)
{
    return (intptr)
        my_syscall(
            (void*)1, /* SYS_write */
            (void*)(intptr)fd,
            (void*)data,
            (void*)nbytes,
            0, /* ignored */
            0  /* ignored */
        );
}

int main(int argc, char* argv[])
{
    write(1, "hello world\n", 13);

    return 0;
}
