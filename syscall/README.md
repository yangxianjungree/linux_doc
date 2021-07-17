
SYSTEM CALL in Linux
==================

- [SYSTEM CALL in Linux](#system-call-in-linux)
  - [1. 什么是系统调用](#1-什么是系统调用)
  - [2. 系统调用的优点](#2-系统调用的优点)
  - [3. 系统调用、POSIX API和C库的关系](#3-系统调用posix-api和c库的关系)
  - [4. 基于C库调用一个系统调用](#4-基于c库调用一个系统调用)
    - [4.1 调用一个系统调用过程总览](#41-调用一个系统调用过程总览)
    - [4.2 封装例程](#42-封装例程)
      - [4.2.1 封装例程简单声明](#421-封装例程简单声明)
      - [4.2.2 libc中write系统调用封装例程示例](#422-libc中write系统调用封装例程示例)
      - [4.2.3 中断号128](#423-中断号128)
      - [4.2.4 初始化系统调用处理程序entry_INT80_32](#424-初始化系统调用处理程序entry_int80_32)
      - [4.2.5 内核注册中断处理程序的实现过程](#425-内核注册中断处理程序的实现过程)
    - [4.3 系统调用处理程序](#43-系统调用处理程序)
      - [4.3.1 system_call 函数](#431-system_call-函数)
      - [4.3.2 旧版本系统处理程序 entry_INT80_32 实现代码](#432-旧版本系统处理程序-entry_int80_32-实现代码)
    - [4.4 服务例程](#44-服务例程)
      - [4.4.1 服务例程定义](#441-服务例程定义)
      - [4.4.2 参数传递](#442-参数传递)
      - [4.4.3 验证参数](#443-验证参数)
      - [4.4.4 访问进程地址空间](#444-访问进程地址空间)
      - [4.4.5 动态地址检查：修正代码（fixup code）（TODO）](#445-动态地址检查修正代码fixup-codetodo)
      - [4.4.6 异常表](#446-异常表)
      - [4.4.7 生成异常表和修正代码](#447-生成异常表和修正代码)
  - [5. 快速系统调用](#5-快速系统调用)
  - [mount系统调用实例分析](#mount系统调用实例分析)
  - [Reference](#reference)


## 1. 什么是系统调用

-------------------

系统调用：操作系统提供给用户进程与内核进行交互的一组接口。


## 2. 系统调用的优点

-------------------

* 在应用程序和硬件之间设置一个额外层，用户不用学习硬件设备的低级编程。例如读写文件时不用管磁盘类型与介质，也不用在乎文件所在文件系统类型；
* 在用户请求某个资源或者权限之前，对用户的权限或请求的正确性进行验证，保证操作系统的稳定和安全；
* 可移植性。内核只需要提供一组相同的接口，用户程序就可以在所有版本的内核之上正确的编译和运行。


## 3. 系统调用、POSIX API和C库的关系

-------------------

* 系统调用通过软中断向内核态发送一个明确的请求；
* 编程接口（API）只是一个函数定义，说明如何获取一个给定的服务；
* 对于开发人员来说，API与系统调用之间的差别没有关系，唯一相关的是函数名、参数类型、返回代码含义。然而对于内核人员来说，系统调用属于内核，用户态的库函数不属于内核。
* POSIX是由IEEE这个组织的一组标准组成，其目标是提供一套大体上基于Unix的可移植操作系统标准。POSIX标准实际上是仿照早期Unix系统的接口建立的。但POSIX标准针对API而不针对系统调用。判断一个系统是否与POSIX兼容要看它是否提供了一组合适的应用程序接口，而不管对应的函数是如何实现。其他的操作系统例如Windows，也提供了与POSIX兼容的库。
* C库实现了Unix系统的主要API，包括标准C库函数和系统调用接口。此外，C库提供了POSIX的绝大部分API。

系统给程序员提供了很多API的库函数。libc（Linux已逐渐不再维护，glibc（GNU C Library）逐渐成为了Linux的标准c库）的标准C库所定义的一些API引用了封装例程（wrapper routine，其唯一目的是发布系统调用）。通常情况下每个系统调用对应一个封装例程，而封装例程定义了应用程序会使用的API。反之不然。一个封装例程可能对应多个系统调用或者不对应系统调用。


## 4. 基于C库调用一个系统调用

-------------------

### 4.1 调用一个系统调用过程总览

当用户态的进程调用一个系统调用时，CPU切换到内核态并开始执行一个内核函数。Linux对系统调用的调用必须通过执行 ```int $0x80``` 汇编指令（Linux老版本唯一方式） 或 ```sysenter``` 或者 ``` syscall ``` 进入内核态（相应分别执行 ```iret``` 或 ```sysexit``` 或 ``` sysret ``` 指令退出内核态）。

<font size=5><u> 第四节都基于旧版系统调用 ```int $0x80``` 展开 </u></font>

因为内核实现了很多不同的系统调用，因此进程必须传递一个叫做系统调用号的参数来识别所需的系统调用，eax寄存器就是作此目的。通常还要传递其他参数。

所有系统调用都返回一个整数值。这些返回值和封装例程的约定是不同的。在内核中返回的整数和0表示系统调用成功结束，而负数表示一个错误条件，代表返回给应用程序的错误码。内核并没有设置或使用errno变量。

```
------------------------------------------------------------------------------------------
|                    用户态                                      内核态                   |
| -----------------------------------------   ------------------------------------------ |
| |                                       |   |   system_call:             sys_xyz() { | |
| |                        xyz() {        |   |       ...                      ...     | |
| |   int main()               ...        |   |       sys_xyz()            }           | |
| |   {                        int 0x80   |   |       ...                              | |
| |       xyz();               ...        |   |   ret_from_sys_call:                   | |
| |       return 0;        }              |   |       ...                              | |
| |   }                                   |   |       iret                             | |
| -----------------------------------------   ------------------------------------------ |
|   应用程序调用           libc中的封装例程         系统调用处理程序         系统调用服务例程 |
------------------------------------------------------------------------------------------
```


### 4.2 封装例程

用户调用系统调用，需要从用户态进入内核态，并将系统调用需要的参数压入相应的寄存器中，内核态的系统调用处理程序就可以从寄存器中取出参数并传递给系统调用服务例程。

封装例程就完成这些工作。用户进程请求某一系统调用的封装例程，然后封装例程就切换到内核态。等系统调用处理程序结束内核工作之后返回到用户态，封装例程就从寄存器中返回值，并设置相应的 errno。

#### 4.2.1 封装例程简单声明

为了简化相应的封装例程的声明，Linux 定义了六个从 ``` _syscall0 ``` 到 ``` _syscall5 ``` 宏。也可以用这些宏简化libc标准库中封装例程的声明。

每个宏名称中的数字0到5对应着相同调用所用的参数号（系统调用号除外），即被压入寄存器的参数个数及顺序。每个宏严格地需要 ``` 2 + 2 x n ``` 个参数，n是系统调用的参数个数。前两个指明系统调用的返回值类型和名字；后面每一对参数指明对应的系统调用参数的类型和名字。

#### 4.2.2 libc中write系统调用封装例程示例

例如 write() 系统调用封装例程的声明是：

```
  _syscall3(int, write, int, fd, const char *, buf, unsigned int, count);
```

libc（或者glibc）对write系统调用的封装例程定义此系统调用宏的形式为：

```
声明：

  _syscall3(int, write, int, fd, const char *, buf, unsigned int, count);

实现展开：

  int write(int fd, const char* buf, unsigned int count)
  {
    long __res;
    asm("int $0x80)
      : "=a" (__res)
      : "0" (__NR_write), "b", ((long)fd),
        "c" ((long)buf), "d" ((long)count));
    
    if ((unsigned log)__res >= (unsigned long)-125) {
      errno = -__res;
      __ret = -1;
    }

    return (int)__res;
  }

```

__NR_write 宏来自 _syscall3 的第二个参数（该宏声明可以在头文件 sys/syscall.h 中找到）。它可以展开成 write 系统调用号。当编译前面的函数时，生成下面的汇编代码：

```
  write:
      pushl %ebx            ; 将ebx推入堆栈
      movl  8(%esp), %ebx   ；将第一个参数放入ebx
      movl  12(%esp), %ecx  ；将第二个参数放入ecx
      movl  16(%esp), %edx  ；将第三个参数放入edx
      movl  $4, %eax        ；将 __NR_write 放入 eax
      int $0x80             ；进行系统调用
      cmpl  $-126, %eax     ；检测返回码
      jbe   .L1             ；如无错跳转
      negl  %eax            ；求eax的补码
      movl  %eax, errno     ；将结果放入errno
      movl  $-1, %eax       ；将eax置为-1
  .L1:  popl  %ebx          ；从堆栈弹出ebx
      ret                   ; 返回调用程序
```

在我个人虚拟机中，因系统版本关系并未使用 ``` int $0x80 ``` 指令进入系统调用处理程序。读者可以从 [5. 快速系统调用](#5-快速系统调用) 看到还有其他的方式进入系统调用处理程序及相关说明。当然，也可以进入子目录 [system_call_without_libc](./system_call_without_libc/README.md) 看看如何在不使用 libc 或者 glibc 的情况下从用户态进入内核态调用系统调用。


#### 4.2.3 中断号128

先决知识：

- 通过生成软件中断来触发内核执行。
- 使用int汇编指令生成软件中断。

Linux内核为中断号 ``` 128（0x80） ``` 注册了一个命名为 ``` entry_INT80_32 ``` 的中断处理程序。

#### 4.2.4 初始化系统调用处理程序entry_INT80_32

在内核初始化期间,内核调用的 ``` trap_init() ``` 函数会建立 ``` def_idts ``` 表中向量128对应的表项。调用的函数： 

```
  idt_setup_from_table(idt_table, def_idts, ARRAY_SIZE(def_idts), true) 
```

该函数通过宏，把一些值装入这个系统中断门（System interrupt gate）描述符的相应域：（中断、陷阱及系统门待研究。）

```
.vector
    IA32_SYSCALL_VECTOR （80）

.bits.ist
    DEFAULT_STACK （0）

.bits.type	
    GATE_INTERRUPT （14）。 表示一个陷阱，相应的处理程序不禁止可屏蔽中断

.bits.dpl
    DPL3（3）。 允许用户态进程调用这个异常处理程序

.bits.p
    1

.addr
    entry_INT80_32。指向异常处理程序

.segment	
    内核代码段__KERNEL_CS的段选择符

```


#### 4.2.5 内核注册中断处理程序的实现过程

注册中断号128（0x80）中断处理程序的实现代码在 ```\linux\arch\x86\kernel\traps.c``` 文件的 ```trap_init``` 函数中：

```
void __init trap_init(void)
{
	...

	idt_setup_traps();

	/*
	 * Should be a barrier for any external CPU state:
	 */
	cpu_init();

	idt_setup_ist_traps();
}

```

该函数会分两次注册中断处理程序表，而我们要看的中断号 ```128（0x80）``` 在 ```idt_setup_traps``` 函数里，实现文件在  ```\linux\arch\x86\kernel\idt.c``` 中：

```c
...
#define DPL0		0x0
#define DPL3		0x3

#define DEFAULT_STACK	0

#define G(_vector, _addr, _ist, _type, _dpl, _segment)	\
	{						\
		.vector		= _vector,		\
		.bits.ist	= _ist,			\
		.bits.type	= _type,		\
		.bits.dpl	= _dpl,			\
		.bits.p		= 1,			\
		.addr		= _addr,		\
		.segment	= _segment,		\
	}

...

/* Interrupt gate */
#define INTG(_vector, _addr)				\
	G(_vector, _addr, DEFAULT_STACK, GATE_INTERRUPT, DPL0, __KERNEL_CS)

/* System interrupt gate */
#define SYSG(_vector, _addr)				\
	G(_vector, _addr, DEFAULT_STACK, GATE_INTERRUPT, DPL3, __KERNEL_CS)

...

static const __initconst struct idt_data def_idts[] = {
  ...
#if defined(CONFIG_IA32_EMULATION)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_compat),
#elif defined(CONFIG_X86_32)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_32),
#endif
};

/**
 * idt_setup_traps - Initialize the idt table with default traps
 */
void __init idt_setup_traps(void)
{
	idt_setup_from_table(idt_table, def_idts, ARRAY_SIZE(def_idts), true);
}

```

简单地将函数和宏展开，我们就可以看到中断号 ```128（0x80）``` 对应表相的各个域。中断号 ```128（0x80）``` 是在 ```\linux\arch\x86\include\asm\irq_vectors.h``` 中声明的：

```
...
#define IA32_SYSCALL_VECTOR		0x80
...

```


### 4.3 系统调用处理程序

在以前文档中，系统调用处理程序是通过 ```system_call()``` 函数实现的。

#### 4.3.1 system_call 函数

它首先把系统调用号和这个异常处理程序可以用到的所有CPU寄存器保存到相应的栈中，除了由控制单元已经自动保存的eflags、cs、eip、ss和esp寄存器,在ds和es中装入内核数据段的段选择符：

```
  system_call:
    pushl %eax
    SAVE_ALL
    movl %esp, %ebx
    andl $0xffffe000, %ebx

```

这个函数也在eax中存放current进程描述符的地址，这是通过获取内核栈指针的值并把它取整到8KB的整数的倍数而完成的。

然后，对用户态传递来的系统调用号进行有效性检查。如果系统调用号无效，函数就把-ENOSYS值放入栈中已保存eax寄存器的单元中。然后跳到ret_from_sys_call()。当进程以这种方式恢复它在用户态的执行时，会在eax中发现一个负的返回码。

接下来，system_call()函数检查是否有调试进程正在跟踪执行的程序对系统调用的调用并处理，最后调用系统调用号所对应的特定服务例程。当服务例程结束时，system_call()函数从eax获取它的返回值，并把返回值存放在曾经保存用户态eax寄存器栈单元的那个位置，如何跳到ret_from_sys_call()函数终止系统调用程序的执行。

```
0xffffff353345   sys_call_num1   sys_call_num1   sys_call_num1  ...
sys_call_table   (4byte)         (4byte)         (4byte)        ...

call *sys_call_table(0, %eax, 44)
 /* 把系统调用号乘以4，再加上system_call_table分派表的起始地址，
  * 然后从这个地址单元获取指向服务例程的指针，内核就找到了要调用的服务例程。
  */

```

当进程恢复它在用户态的执行时，就可以从eax中找到系统调用的返回码。

#### 4.3.2 旧版本系统处理程序 entry_INT80_32 实现代码

内核根据硬件或兼容的情况，系统处理程序有几种不同的实现。在内核v5.9-rc8版本中的旧版本系统调用处理程序 ```entry_INT80_32``` 的实现代码在 ```\linux\arch\x86\entry\entry_32.S``` 中：

```asm

/*
 * 32-bit legacy system call entry.
 *
 * 32-bit x86 Linux system calls traditionally used the INT $0x80
 * instruction.  INT $0x80 lands here.
 *
 * ...
 *
 * This is considered a slow path.  It is not used by most libc
 * implementations on modern hardware except during process startup.
 *
 * Arguments:
 * eax  system call number
 * ebx  arg1
 * ecx  arg2
 * edx  arg3
 * esi  arg4
 * edi  arg5
 * ebp  arg6
 */
SYM_FUNC_START(entry_INT80_32)
	ASM_CLAC
	pushl	%eax			/* pt_regs->orig_ax */

	SAVE_ALL pt_regs_ax=$-ENOSYS switch_stacks=1	/* save rest */

	movl	%esp, %eax
	call	do_int80_syscall_32
.Lsyscall_32_done:
	STACKLEAK_ERASE

restore_all_switch_stack:
	SWITCH_TO_ENTRY_STACK
	CHECK_AND_APPLY_ESPFIX

	/* Switch back to user CR3 */
	SWITCH_TO_USER_CR3 scratch_reg=%eax
  ...
	jmp	handle_exception
SYM_CODE_END(asm_iret_error)
.previous
	_ASM_EXTABLE(.Lirq_return, asm_iret_error)
SYM_FUNC_END(entry_INT80_32)

```

 entry_INT80_32 系统调用处理程序会调用 ``` do_int80_syscall_32``` ，该函数的实现在 ``` \linux\arch\x86\entry\common.c ``` 里。``` do_int80_syscall_32``` 函数会从用户模式进入内核模式，然后根据系统调用号查找系统调用服务例程，将返回结果保存到ax寄存器。

```c
...
static __always_inline unsigned int syscall_32_enter(struct pt_regs *regs)
{
	if (IS_ENABLED(CONFIG_IA32_EMULATION))
		current_thread_info()->status |= TS_COMPAT;

	return (unsigned int)regs->orig_ax;
}

/*
 * Invoke a 32-bit syscall.  Called with IRQs on in CONTEXT_KERNEL.
 */
static __always_inline void do_syscall_32_irqs_on(struct pt_regs *regs,
						  unsigned int nr)
{
	if (likely(nr < IA32_NR_syscalls)) {
		instrumentation_begin();
		nr = array_index_nospec(nr, IA32_NR_syscalls);
		regs->ax = ia32_sys_call_table[nr](regs);
		instrumentation_end();
	}
}

/* Handles int $0x80 */
__visible noinstr void do_int80_syscall_32(struct pt_regs *regs)
{
	unsigned int nr = syscall_32_enter(regs);

	/*
	 * Subtlety here: if ptrace pokes something larger than 2^32-1 into
	 * orig_ax, the unsigned int return value truncates it.  This may
	 * or may not be necessary, but it matches the old asm behavior.
	 */
	nr = (unsigned int)syscall_enter_from_user_mode(regs, nr);

	do_syscall_32_irqs_on(regs, nr);
	syscall_exit_to_user_mode(regs);
}

```


### 4.4 服务例程

#### 4.4.1 服务例程定义

系统调用服务例程的定义一般通过 ``` SYSCALL_DEFINE* ``` 实现。这个宏和封装例程的 ``` _syscall* ``` 宏类似，可以参考 [4.2 封装例程](#42-封装例程)。例如:

```
SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
    char __user *, type, unsigned long, flags, void __user *, data)

展开：
asmlinkage long sys_mount(char __user * dev_name, char __user * dir_name,
    char __user * type, unsigned long flags, void __user * data);
```
asmlinkage是个宏，使用它是为了保持参数在stack中。系统调用是先将参数压入stack以后调用sys_*函数的，所以所有的sys_*函数都有asmlinkage来告诉编译器不要使用寄存器来编译

系统调用处理程序通过系统调用号和sys_call_table找到服务例程函数后，还要将用户进程参数传递给内核、验证等后续步骤，然后完成系统调用的服务功能。

#### 4.4.2 参数传递

  普通函数的参数传递是通过把参数传递写进活动的程序栈（或者用户态栈或者内核态堆栈）。但是系统调用的参数通常是传递给系统调用处理程序在CPU中的寄存器，然后拷贝到内核态堆栈，这是因为系统调用服务例程是用户态的普通C函数。

#### 4.4.3 验证参数

  检查类型依赖于系统调用与特定的参数。

#### 4.4.4 访问进程地址空间

  系统调用服务例程需要频繁的读写进程地址空间的数据。Linux提供了一组宏使访问更加容易。例如get_user()和put_user()。
  
#### 4.4.5 动态地址检查：修正代码（fixup code）（TODO）

  用户进程可能因为传递一个错误的地址引起“缺页”中断。因此必须由缺页处理程序对引起缺页中断情况进行区分，并采取不同的处理行为。

#### 4.4.6 异常表

#### 4.4.7 生成异常表和修正代码


## 5. 快速系统调用

-------------------


Linux上的传统系统调用接口需要两个条件：

- 通过生成软件中断来触发内核执行。
  
- 使用int汇编指令生成软件中断。


## mount系统调用实例分析

-------------------




## Reference

-------------------

* 《深入理解Linux内核(第三版)中文版》
* 《Linux内核设计与实现(第三版)中文版》
