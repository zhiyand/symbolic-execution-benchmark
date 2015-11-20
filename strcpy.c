//strcpy.c

#include <stdio.h>

int main(int argc, char ** argv){

	char buf[10];

	if(argc!=2){
		printf("Incorrect number of inputs!\n");
	}
	else{
		strcpy(buf,argv[1]);
		printf("you had typed: %s\n",buf);
	}

}