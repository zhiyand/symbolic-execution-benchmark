fuzzball ../strcpy.out -solver stpvc -linux-syscalls  -tracepoint 0x080484d1:'mem[R_ESP:reg32_t + 0x22:reg32_t ]:reg32_t' -symbolic-region 0xbfffd004+20 -trace-iterations -solve-final-pc -- ../strcpy.out hello

