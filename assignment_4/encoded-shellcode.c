#include<stdio.h>
#include<string.h>

unsigned char buf[] = "";

main()
{
    printf("Malicious shellcode length: %d\n", strlen(buf));
	int (*hmm)()=(int(*)())buf;
	hmm();
    return 0;
}

	
