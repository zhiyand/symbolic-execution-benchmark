llvm-gcc --emit-llvm -c -g ../strcpy.c &&
cp strcpy.o ../ && 
klee --posix-runtime --libc=uclibc --max-time=360 --watchdog ../strcpy.o --sym-args 0 1 30 --sym-files 1 10 --sym-stdout
