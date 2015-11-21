fuzzball ../array.out -solver stpvc -linux-syscalls -skip-call-ret-symbol 0x080483ea=x -finish-on-nonfalse-cond -check-condition-at 0x08048434:'mem[R_ESP:reg32_t + 0x68:reg32_t]:reg32_t >= 0x14:reg32_t' -fuzz-start-addr 0x080483d4 -trace-iterations -solve-final-pc -- ../array.out 0

