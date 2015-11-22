llvm-gcc --emit-llvm -c -g ../doublefree.c &&
cp doublefree.o ../ && 
klee --posix-runtime --libc=uclibc --max-time=360 --watchdog ../doublefree.o --sym-args 0 2 2 --sym-files 1 10 --sym-stdout