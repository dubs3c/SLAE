
import sys
import random

def class Randomized(object):

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


