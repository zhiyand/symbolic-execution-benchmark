//gets.c

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char ** argv){

	char name[10];
	printf("Please enter a maximum 10 char name\n");
	gets(name);
	printf("Hi %s!\n",name);
}