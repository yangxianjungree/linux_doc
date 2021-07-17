all: libc_printf libc_puts libc_syscall

libc_printf: printf.c
	gcc printf.c -o libc_printf

libc_puts: puts.c
	gcc puts.c -o libc_puts

libc_syscall: syscall.c
	gcc syscall.c -o libc_syscall

clean:
	rm -rf libc_*
