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
