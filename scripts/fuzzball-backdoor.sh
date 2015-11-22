fuzzball ../backdoor.out -solver stpvc -linux-syscalls -skip-call-ret-symbol 0x0804845c=x -trace-iterations -solve-final-pc -- ../backdoor.out 0

