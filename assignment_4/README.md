
# Custom encoder for bypassing signature based detection

Malware detection techniques has improved a lot over the years. Today companies are investing in machine learning methods for detecting malware, which sounds pretty cool if you ask me. However, there is one method that has been used since the first anti-virus software, which is signature based detection.

When disassembling a program you can analyze the assembly instructions in order to understand the program from the lowest level. It's also possible from the assembly code to identify a set of unique instructions that identifies a specific program. These unique instructions form the signature. The instructions can be anything that identifies a specific and unique behaviour in the program. An example could be a decryption routine that identifies perhaps a decryption stub used for decrypting shellcode.

How do we bypass signature detections? Well, we change the signature. You either do this manually or you write an encoder which takes shellcode as input and outputs an encoded shellcode, which as zero known signatures for it. In this article, I will present a very easy and trivial encoding scheme for from AVs :)

## The Algorithm

The scheme I have chosen is a simple insertion encoder with XOR twist. Given a piece of shellcode, the encoder will insert a value between 1-255 as a prefix for each shellcode byte. This value will then be XORed with the shellcode byte. This method has some drawbacks:

    1) It will double the shellcode length 
    2) Once the shellcode has been decoded, a bunch of garbage data will exist folling the shellcode. This means that if your shellcode does not return, the garbage data will be executed which leads to a segfault.

For demonstrating how bypassing signature detection looks like, this method will suffice.

## The Encoder

I have chosen to write the encoder in Python because it's very easy to implement these kinds of scripts in it.

```python


```


## Writing the decoder stub



---
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[https://www.pentesteracademy.com/course?id=3](https://www.pentesteracademy.com/course?id=3)

Student ID: SLAE-1490
