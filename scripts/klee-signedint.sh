llvm-gcc --emit-llvm -c -g ../signedint.c &&
cp signedint.o ../ && 
klee --posix-runtime --libc=uclibc --max-time=360 --watchdog ../signedint.o --sym-args 0 1 100  --sym-files 1 10 --sym-stdout
