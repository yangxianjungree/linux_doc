
SYSTEM CALL WITHOUT LIBC
========================

在大多数的用户进程中调用系统都要通过glibc的封装例程。当然，我们也可以使用汇编，将系统调用所需要的系统调用号和参数传入相应的寄存器，通过进入系统调用处理程序的中断之类进入内核态；然后交由内核完成后续的操作；最后，我们从存有系统调用返回值的寄存器中取回返回值。这样，我们就完成了一次在没有glibc库的情况下的系统调用。


本文以调用一次 write 系统调用为例。


- [SYSTEM CALL WITHOUT LIBC](#system-call-without-libc)
    - [syscall 封装](#syscall-封装)
    - [start 函数封装](#start-函数封装)
    - [syscall 和 start 代码示例](#syscall-和-start-代码示例)
    - [main 函数](#main-函数)
    - [main 函数代码示例](#main-函数代码示例)
    - [反汇编信息简单梳理](#反汇编信息简单梳理)


### syscall 封装

1.用户应用程序使用的整数寄存器的传递顺序依次是％rdi ，％rsi，％rdx，％rcx，％r8和％r9。内核态从％rdi，％rsi，％rdx，％r10，％r8和％r9寄存器中取相应的参数。

2.通过syscall指令完成系统调用。内核销毁寄存器％rcx和％r11。

3.必须在寄存器％rax中传递syscall的编号。

4.系统调用仅限于六个参数，参数不会在堆栈上传递，因为应用进程在用户态，系统调用服务例程在内核态。

5.从系统调用返回，寄存器％rax包含系统调用的结果。-4095到-1之间的值表示错误，它是-errno。

6.仅将INTEGER类型或MEMORY的地址值传递给内核。


### start 函数封装

系统在创建一个新进程时，会从磁盘中读取ELF格式的可执行文件的数据，然后加载到进程结构体的相应字段中。最后从代码段中读取指令数据并执行。而代码段一般都是由 ``` _start ``` 标签指向，也就是 _start 是进程创建完毕后真正第一次执行的地方。start 函数完成一些基本初始化工作之后，会跳到我们熟知的 main 函数中执行。

### syscall 和 start 代码示例

```
stephen@stephen:~/proj/SYSTEMCALL/system_call_without_libc$ cat assm_syscall.S

.intel_syntax noprefix
.text
    .globl _start, my_syscall

    _start:
	// _start function
	
        xor rbp,rbp  /* xoring a value with itself = 0 */
        pop rdi      /* rdi = argc */
        	     /* the pop instruction already added 8 to rsp */
        mov rsi,rsp  /* rest of the stack as an array of char ptr */

        and rsp,-16
        call main    // call main function 

	// _EXIT
	// man 2 _EXIT
	mov rdi,rax /* syscall param 1 = rax (ret value of main) */
        mov rax,60 /* SYS_exit */
        syscall
	ret

    my_syscall:
        mov rax,rdi
        mov rdi,rsi
        mov rsi,rdx
        mov rdx,rcx
        mov r10,r8
        mov r8,r9
        syscall
        ret

```

### main 函数

在 main 函数中，主要就调用系统调用封装例程。因此，我们要简单封装一下前面的汇编代码，使我们的 main 函数里面能找系统调用封装例程的符号。

### main 函数代码示例

```
stephen@stephen:~/proj/SYSTEMCALL/system_call_without_libc$ cat assm_syscall.c

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

```


### 反汇编信息简单梳理

从反汇编的信息可以看到，我们进程创建后，会从 0x0000000000001030 这个代码段地址开始执行代码。这个地址正是我们的 start 函数地址。start 函数完成例如初始化 main 函数参数之后，调用 main 函数（起始地址是 0000000000001000）。我们的 main 函数调用系统调用封装例程（000000000000104d），然后将用户数据压入相应的寄存器之后，通过 syscall 汇编指令进入内核态并执行系统调用处理程序和系统调用服务例程（当然这里我们是看不到的）。系统调用完成后，main 函数处理返回值，然后回到 start 函数。 start 函数然后调用 SYS_exit （0x3c） 系统调用退出整个进程。

```
stephen@stephen:~/proj/SYSTEMCALL/system_call_without_libc$ make
stephen@stephen:~/proj/SYSTEMCALL/system_call_without_libc$ objdump -dSsx nolibc

nolibc:     file format elf64-x86-64
nolibc
architecture: i386:x86-64, flags 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
start address 0x0000000000001030
...
...
Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .interp       0000001c  00000000000002a8  00000000000002a8  000002a8  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
...
  5 .text         00000062  0000000000001000  0000000000001000  00001000  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
...
...
Contents of section .rodata:
 2000 68656c6c 6f20776f 726c640a 00        hello world..
...
...
Disassembly of section .text:

0000000000001000 <.text>:
    1000:       f3 0f 1e fa             endbr64
    1004:       48 83 ec 08             sub    $0x8,%rsp
    1008:       45 31 c9                xor    %r9d,%r9d
    100b:       45 31 c0                xor    %r8d,%r8d
    100e:       b9 0d 00 00 00          mov    $0xd,%ecx
    1013:       48 8d 15 e6 0f 00 00    lea    0xfe6(%rip),%rdx        # 0x2000
    101a:       be 01 00 00 00          mov    $0x1,%esi
    101f:       bf 01 00 00 00          mov    $0x1,%edi
    1024:       e8 24 00 00 00          callq  0x104d
    1029:       31 c0                   xor    %eax,%eax
    102b:       48 83 c4 08             add    $0x8,%rsp
    102f:       c3                      retq
    1030:       48 31 ed                xor    %rbp,%rbp
    1033:       5f                      pop    %rdi
    1034:       48 89 e6                mov    %rsp,%rsi
    1037:       48 83 e4 f0             and    $0xfffffffffffffff0,%rsp
    103b:       e8 c0 ff ff ff          callq  0x1000
    1040:       48 89 c7                mov    %rax,%rdi
    1043:       48 c7 c0 3c 00 00 00    mov    $0x3c,%rax
    104a:       0f 05                   syscall
    104c:       c3                      retq
    104d:       48 89 f8                mov    %rdi,%rax
    1050:       48 89 f7                mov    %rsi,%rdi
    1053:       48 89 d6                mov    %rdx,%rsi
    1056:       48 89 ca                mov    %rcx,%rdx
    1059:       4d 89 c2                mov    %r8,%r10
    105c:       4d 89 c8                mov    %r9,%r8
    105f:       0f 05                   syscall
    1061:       c3                      retq

```