all: assm_syscall.S assm_syscall.c
	gcc -s -O2 -nostdlib assm_syscall.S assm_syscall.c -o nolibc

clean:
	rm -rf nolibc
