all: libc_printf libc_puts

libc_printf: main.c
	gcc main.c -o libc_printf

libc_puts: puts.c
	gcc puts.c -o libc_puts

clean:
	rm -rf libc_printf libc_puts
