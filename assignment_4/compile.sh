#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o build/$1.o $1.nasm

echo '[+] Linking ...'
ld -o build/$1 build/$1.o

echo '[+] Done!'



