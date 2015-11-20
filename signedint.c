//signedint.c

#include <stdio.h>

int main(int argc, char **argv){

	int bufLen = 10;
	char buf[bufLen];
	if(argc!=2){
		printf("Incorrect number of inputs!\n");
	}
	else{
		if(strlen(argv[1])>bufLen){
			printf("argument length is too long!\n");
		}
		else{
			strcpy(buf,argv[1]);
		}
	}

}