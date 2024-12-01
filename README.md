<h2>Simple hello world in the address of the function execute</h2>

``` c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
    // Hexadecimal shellcode to print "Hello, World!"
    unsigned char shellcode[] = 
        "\xeb\x1e"                        // JMP SHORT +30 bytes
        "\x48\x31\xc0"                    // XOR RAX, RAX
        "\x48\x89\xc2"                    // MOV RDX, RAX
        "\x48\x89\xc6"                    // MOV RSI, RAX
        "\x48\x8d\x3d\x0a\x00\x00\x00" // LEA RDI, [RIP+10]
        "\xb0\x01"                        // MOV AL, 1 (sys_write)
        "\x48\xc7\xc2\x0d\x00\x00\x00" // MOV RDX, 13 (length of message)
        "\x0f\x05"                        // SYSCALL
        "\xe8\xdd\xff\xff\xff"          // CALL -35 bytes
        "Hello, World!\n";                 // String

    printf("Shellcode length: %ld bytes\n", sizeof(shellcode) - 1);

    // Cast the shellcode pointer to a function and execute it
    void (*execute)() = (void (*)())shellcode;
    execute();

    return 0;
}
```
<h2>Hello world but you choose the memory address where to execute it</h2>

``` c
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned char shellcode[] = 
    "\xeb\x1e"                        // JMP SHORT +30 bytes
    "\x48\x31\xc0"                    // XOR RAX, RAX
    "\x48\x89\xc2"                    // MOV RDX, RAX
    "\x48\x89\xc6"                    // MOV RSI, RAX
    "\x48\x8d\x3d\x0a\x00\x00\x00" // LEA RDI, [RIP+10]
    "\xb0\x01"                        // MOV AL, 1 (sys_write)
    "\x48\xc7\xc2\x0d\x00\x00\x00" // MOV RDX, 13 (length of message)
    "\x0f\x05"                        // SYSCALL
    "\xe8\xdd\xff\xff\xff"          // CALL -35 bytes
    "Hello, World!\n";                 // String

int main() {
    char input[20];
    void *address;

    printf("Enter memory address in hexadecimal (e.g., 0x7fffffffe000): ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Error reading input.\n");
        return 1;
    }

    address = (void *)strtoull(input, NULL, 16);

    if (address == NULL || mprotect((void *)((size_t)address & ~(getpagesize() - 1)), getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        fprintf(stderr, "Invalid or inaccessible memory address.\n");
        return 1;
    }

    memcpy(address, shellcode, sizeof(shellcode));

    printf("Executing shellcode at address: %p\n", address);
    void (*execute)() = (void (*)())address;
    execute();

    return 0;
}
``` 

