all: array.o strcpy.o doublefree.o signedint.o backdoor.o gets.o

%.o: %.c
	gcc $< -o $@

clean:
	rm -rf *.o
