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
