llvm-gcc --emit-llvm -c -g ../gets.c &&
cp gets.o ../ && 
klee --posix-runtime --libc=uclibc --max-time=360 --watchdog ../gets.o --sym-args 0 2 2 --sym-files 1 100 --sym-stdout