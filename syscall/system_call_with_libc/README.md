# SYSTEM CALL WITH LIBC

-------------------

工作中，我们一般都通过glibc的封装例程使用系统调用。glibc中可能多个封装例程对应一个系统调用，可能一个封装对应一个系统调用，也有可能一个对应多个。在我们程序运行之前，系统创建进程时会从glibc动态库中将程序代码中调用的封装例程实现代码映射到进程的地址空间。所以我们编译好的程序是无法通过反汇编自己的可执行文件查看封装例程的实现的。应该可以在程序运行时通过gdb看，毕竟封装例程也在用户态运行。

本文以调用一次 write 系统调用的一系列封装例程为例。

- [SYSTEM CALL WITH LIBC](#system-call-with-libc)
  - [printf 库函数](#printf-库函数)
    - [puts 库例程](#puts-库例程)
    - [syscall 库函数](#syscall-库函数)
    - [总结](#总结)

## printf 库函数

-------------------

- 简单调用 printf 代码

``` c
stephen@stephen:~/proj/SYSTEMCALL/system_call_with_libc$ cat printf.c 
#include <stdio.h>

int main(int argc, char* argv)
{
 printf("hello, world.\n");

 return 0;
}

```

- 生成可执行文件libc_printf之后，我们对其进行反汇编，可以看到printf的实现其实是调用了puts函数。

``` asm
stephen@stephen:~/proj/SYSTEMCALL/system_call_with_libc$ objdump -dSsx libc_printf

libc_printf:     file format elf64-x86-64
libc_printf
architecture: i386:x86-64, flags 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
start address 0x0000000000001060
...
...

0000000000001050 <puts@plt>:
    1050:       f3 0f 1e fa             endbr64
    1054:       f2 ff 25 75 2f 00 00    bnd jmpq *0x2f75(%rip)        # 3fd0 <puts@GLIBC_2.2.5>
    105b:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000001060 <_start>:
    1060:       f3 0f 1e fa             endbr64
    1064:       31 ed                   xor    %ebp,%ebp
    1066:       49 89 d1                mov    %rdx,%r9
    1069:       5e                      pop    %rsi
    106a:       48 89 e2                mov    %rsp,%rdx
    106d:       48 83 e4 f0             and    $0xfffffffffffffff0,%rsp
    1071:       50                      push   %rax
    1072:       54                      push   %rsp
    1073:       4c 8d 05 66 01 00 00    lea    0x166(%rip),%r8        # 11e0 <__libc_csu_fini>
    107a:       48 8d 0d ef 00 00 00    lea    0xef(%rip),%rcx        # 1170 <__libc_csu_init>
    1081:       48 8d 3d c1 00 00 00    lea    0xc1(%rip),%rdi        # 1149 <main>
    1088:       ff 15 52 2f 00 00       callq  *0x2f52(%rip)        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
    108e:       f4                      hlt
    108f:       90                      nop
...
...
0000000000001149 <main>:
    1149:       f3 0f 1e fa             endbr64
    114d:       55                      push   %rbp
    114e:       48 89 e5                mov    %rsp,%rbp
    1151:       48 83 ec 10             sub    $0x10,%rsp
    1155:       89 7d fc                mov    %edi,-0x4(%rbp)
    1158:       48 89 75 f0             mov    %rsi,-0x10(%rbp)
    115c:       48 8d 3d a1 0e 00 00    lea    0xea1(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    1163:       e8 e8 fe ff ff          callq  1050 <puts@plt>
    1168:       b8 00 00 00 00          mov    $0x0,%eax
    116d:       c9                      leaveq
    116e:       c3                      retq
    116f:       90                      nop
...
```

- 查看运行这段代码的进程所调用的所有系统

``` shell
stephen@stephen:~/proj/SYSTEMCALL/system_call_with_libc$ strace ./libc_printf 
execve("./libc_printf", ["./libc_printf"], 0x7ffd77782f80 /* 60 vars */) = 0
brk(NULL)                               = 0x5608c5772000
arch_prctl(0x3001 /* ARCH_??? */, 0x7ffd458b2890) = -1 EINVAL (Invalid argument)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=74362, ...}) = 0
mmap(NULL, 74362, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fcfce003000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\360q\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0", 32, 848) = 32
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0cBR\340\305\370\2609W\242\345)q\235A\1"..., 68, 880) = 68
fstat(3, {st_mode=S_IFREG|0755, st_size=2029224, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fcfce001000
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0", 32, 848) = 32
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0cBR\340\305\370\2609W\242\345)q\235A\1"..., 68, 880) = 68
mmap(NULL, 2036952, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7fcfcde0f000
mprotect(0x7fcfcde34000, 1847296, PROT_NONE) = 0
mmap(0x7fcfcde34000, 1540096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x25000) = 0x7fcfcde34000
mmap(0x7fcfcdfac000, 303104, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x19d000) = 0x7fcfcdfac000
mmap(0x7fcfcdff7000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e7000) = 0x7fcfcdff7000
mmap(0x7fcfcdffd000, 13528, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7fcfcdffd000
close(3)                                = 0
arch_prctl(ARCH_SET_FS, 0x7fcfce002540) = 0
mprotect(0x7fcfcdff7000, 12288, PROT_READ) = 0
mprotect(0x5608c3bbd000, 4096, PROT_READ) = 0
mprotect(0x7fcfce043000, 4096, PROT_READ) = 0
munmap(0x7fcfce003000, 74362)           = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x1), ...}) = 0
brk(NULL)                               = 0x5608c5772000
brk(0x5608c5793000)                     = 0x5608c5793000
write(1, "hello, world.\n", 14hello, world.
)         = 14
exit_group(0)                           = ?
+++ exited with 0 +++
```

### puts 库例程

可以仿照 printf 函数再来一遍，结果和上面差不多：

``` c
stephen@stephen:~/proj/SYSTEMCALL/system_call_with_libc$ cat puts.c 
#include <stdio.h>

int main(int argc, char* argv)
{
 puts("hello, world.\n");

 return 0;
}
stephen@stephen:~/proj/SYSTEMCALL/system_call_with_libc$ make libc_puts 
gcc puts.c -o libc_puts
stephen@stephen:~/proj/SYSTEMCALL/system_call_with_libc$ objdump -dSsx libc_puts
...
stephen@stephen:~/proj/SYSTEMCALL/system_call_with_libc$ strace ./libc_puts
...
```

### syscall 库函数

- 代码

``` c
stephen@stephen:~/proj/SYSTEMCALL/system_call_with_libc$ cat syscall.c 
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>

int main()
{
 const char* buf = "hello, world.\n";
 syscall(__NR_write, STDOUT_FILENO, buf, strlen(buf));

 return 0;
}
```

- 反汇编

``` asm
stephen@stephen:~/proj/SYSTEMCALL/system_call_with_libc$ objdump -dSsx libc_syscall
...
0000000000001169 <main>:
    1169:       f3 0f 1e fa             endbr64
    116d:       55                      push   %rbp
    116e:       48 89 e5                mov    %rsp,%rbp
    1171:       48 83 ec 10             sub    $0x10,%rsp
    1175:       48 8d 05 88 0e 00 00    lea    0xe88(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    117c:       48 89 45 f8             mov    %rax,-0x8(%rbp)
    1180:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    1184:       48 89 c7                mov    %rax,%rdi
    1187:       e8 d4 fe ff ff          callq  1060 <strlen@plt>
    118c:       48 89 c2                mov    %rax,%rdx
    118f:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    1193:       48 89 d1                mov    %rdx,%rcx
    1196:       48 89 c2                mov    %rax,%rdx
    1199:       be 01 00 00 00          mov    $0x1,%esi
    119e:       bf 01 00 00 00          mov    $0x1,%edi
    11a3:       b8 00 00 00 00          mov    $0x0,%eax
    11a8:       e8 c3 fe ff ff          callq  1070 <syscall@plt>
    11ad:       b8 00 00 00 00          mov    $0x0,%eax
    11b2:       c9                      leaveq
    11b3:       c3                      retq
    11b4:       66 2e 0f 1f 84 00 00    nopw   %cs:0x0(%rax,%rax,1)
    11bb:       00 00 00
    11be:       66 90                   xchg   %ax,%ax
...
```

- 执行时系统调用

``` shell
stephen@stephen:~/proj/SYSTEMCALL/system_call_with_libc$ strace ./libc_syscall 
execve("./libc_syscall", ["./libc_syscall"], 0x7ffc11854a50 /* 60 vars */) = 0
brk(NULL)                               = 0x557789e4f000
arch_prctl(0x3001 /* ARCH_??? */, 0x7fff81b21a10) = -1 EINVAL (Invalid argument)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=74362, ...}) = 0
mmap(NULL, 74362, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f3d54c40000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\360q\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0", 32, 848) = 32
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0cBR\340\305\370\2609W\242\345)q\235A\1"..., 68, 880) = 68
fstat(3, {st_mode=S_IFREG|0755, st_size=2029224, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f3d54c3e000
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0", 32, 848) = 32
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0cBR\340\305\370\2609W\242\345)q\235A\1"..., 68, 880) = 68
mmap(NULL, 2036952, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f3d54a4c000
mprotect(0x7f3d54a71000, 1847296, PROT_NONE) = 0
mmap(0x7f3d54a71000, 1540096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x25000) = 0x7f3d54a71000
mmap(0x7f3d54be9000, 303104, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x19d000) = 0x7f3d54be9000
mmap(0x7f3d54c34000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e7000) = 0x7f3d54c34000
mmap(0x7f3d54c3a000, 13528, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f3d54c3a000
close(3)                                = 0
arch_prctl(ARCH_SET_FS, 0x7f3d54c3f540) = 0
mprotect(0x7f3d54c34000, 12288, PROT_READ) = 0
mprotect(0x557789227000, 4096, PROT_READ) = 0
mprotect(0x7f3d54c80000, 4096, PROT_READ) = 0
munmap(0x7f3d54c40000, 74362)           = 0
write(1, "hello, world.\n", 14hello, world.
)         = 14
exit_group(0)                           = ?
+++ exited with 0 +++
```

### 总结

printf、puts、syscall(__NR_write, ...) 最终都调用了write系统调用。在进程实际执行打印这个操作时，printf和puts两个库函数，相对于syscall来说进程多执行了 fstat 和 brk 两个系统调用，原因需要继续分析。
