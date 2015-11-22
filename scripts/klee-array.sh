llvm-gcc --emit-llvm -c -g ../array.c &&
cp array.o ../ && 
klee --posix-runtime --libc=uclibc --max-time=360 --watchdog ../array.o --sym-args 0 1 30 --sym-files 1 10 --sym-stdout
