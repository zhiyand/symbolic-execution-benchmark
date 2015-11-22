llvm-gcc --emit-llvm -c -g ../backdoor.c &&
cp backdoor.o ../ && 
klee --posix-runtime --libc=uclibc --max-time=360 --watchdog ../backdoor.o --sym-args 0 2 2 --sym-files 1 10 --sym-stdout