fuzzball ../signedint.out -solver stpvc -linux-syscalls -check-condition-at 0x080484a9:'R_EDX:reg32_t < 0x00:reg32_t' -tracepoint 0x080484a9:'R_EDX:reg32_t' -tracepoint 0x08048414:'mem[R_ECX:reg32_t + 0x4:reg32_t]:reg32_t' -symbolic-string16 0xbffffec2+4096 -finish-on-nonfalse-cond -trace-iterations -fuzz-start-addr 0x08048414 -solve-final-pc -- ../signedint.out hello

