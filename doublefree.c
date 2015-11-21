//doublefree.c

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv){
	char *buf;
	buf = (char*) malloc(15);
	if(argc!=2){
		printf("Incorrect number of inputs!\n");
		
	}
	else{
		int num = atoi(argv[1]);
		free(buf);
		if(num>10){
			free(buf);
		}
	}
}