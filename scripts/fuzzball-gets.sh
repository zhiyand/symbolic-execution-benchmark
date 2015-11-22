fuzzball ../gets.out -solver stpvc -linux-syscalls -skip-call-ret-symbol 0x08048390=x -fuzz-start-addr 0x08048494 -trace-iterations -solve-final-pc -- ../gets.out

