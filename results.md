# Results of Benchmarking

This benchmark was run on each of the three tools under comparison:

* Klee
* FuzzBALL
* angr

The purpose was to compare how these tools handle path pruning.

## Programs in the benchmark

### `array.c`

This is a simple demonstration of array access out-of-bound errors.
The program accepts one argument that is an integer. Any value greater
than 19 should result in a memory access out of the boundary of the
array. Values larger than or equal to 23 will result in a segmentation
fault.

### `strcpy.c`

This is a simple demonstration of memory out-of-bound error. 
The program will accept one argument as a string.  Memory out-of-bound error
will be triggered when the number of characters in the string is more than 10.

### `signedint.c`

This is a simple demonstration of an signed int vulnerability.
The check for the length of the argument will pass when the length of
the arugment provided is so long such that it resulted in an integer
overflow (looping back to negative value). This will cause strcpy to copy
an input with length more than the size of the allocated buffer, resulting
in an memory out-of-point error

### `gets.c`
This is a simple demonstration of how gets did not check for the 
length of the input. An input with length more than 10 will trigger
a memory out-of-bounds error

###`doublefree.c`
This is a simple demonstration of double free vulnerability.
If the argument (an integer) is more than 10, it will trigger
a double free vulnerability.

### `backdoor.c`

A demonstration of logic vulnerability. The program should only execute
`admin_code()` when `uid` (provided by first command-line argument 1)
is equal to `1`. This is enforced by the `authenticate()` function.
However, there is a backdoor, when `uid` is 2, the `authenticate()`
function is bypassed.

There're no crashes expected with this program. The bug is a logic bug.
`

## Observations (`array.c`)

**`array.c` on `angr`**

```
<Explorer with paths: 2 active, 0 spilled, 23 deadended, 2799 errored, 0 unconstrained, 0 found, 0 avoided, 0 deviating, 0 looping, 0 lost>
```

23 paths exited normally. 2799 paths errored out. `angr` kept running
(generating more errored paths) until manually interuption.

**`array.c` on `klee`**
```
KLEE: done: explored paths = 13809
KLEE: done: avg. constructs per query = 115
KLEE: done: total queries = 8294
KLEE: done: valid queries = 5924
KLEE: done: invalid queries = 2370
KLEE: done: query cex = 8294

KLEE: done: total instructions = 1211969
KLEE: done: completed paths = 13809
KLEE: done: generated tests = 13776

KLEE: ERROR: /home/student/cs5231/KLEE/klee-uclibc/libc/stdlib/stdlib.c:526: memory error: out of bound pointer
KLEE: ERROR: /home/student/Desktop/benchmarks/scripts/../array.c:16: memory error: out of bound pointer

```
`klee` kept running until time-out of 360 seconds.

**`array.c` on `fuzzBALL`**
```
Iteration 1:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 2:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 3:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 4:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 5:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 6:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 7:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 8:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 9:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 10:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 11:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 12:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 13:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 14:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 15:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 16:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 17:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is false
Iteration 18:
At 0x08048434, condition  0x14:reg32_t <= mem_70[ R_ESP_1:reg32_t + 0x68:reg32_t ]:reg32_t  is true
```
We specify that the counter variable for the for-loop should not exceed a certain value (20), and we look
into the variable's address location to check on each iteration (Path generated). `fuzzBALL` generated
random symbolic arguments until it hit a case (On its 18th try) that satisfy this condition, thus automatically
terminating itself.


## Observations (`strcpy.c`)

**`strcpy.c` on `angr`**

```
<PathGroup with 2 deadended>
```

Two paths were identified, which is correct. But finding the specific bug requires specifying
the input string length, which is not very useful in this case.

**`strcpy.c` on `klee`**
```
KLEE: done: explored paths = 12
KLEE: done: avg. constructs per query = 12
KLEE: done: total queries = 21
KLEE: done: valid queries = 1
KLEE: done: invalid queries = 20
KLEE: done: query cex = 21

KLEE: done: total instructions = 10694
KLEE: done: completed paths = 12
KLEE: done: generated tests = 12

KLEE: ERROR: /home/student/cs5231/KLEE/klee-uclibc/libc/string/strcpy.c:27: memory error: out of bound pointer
```

**`strcpy.c` on `fuzzBALL`**
```
Iteration 121:
: error while loading shared libraries: cannot open shared object file: No such file or directory
Iteration 122:
At 080484d1, mem[R_ESP:reg32_t + 0x22:reg32_t ]:reg32_t is 0xb7f0:reg32_t
�#��29d typed: n�I1

*** stack smashing detected ***: <unknown> terminated
```
Manual termination required. A region of the buffer is symbolized, and FuzzBALL works from there.


##observations

**`signedint.c` on `angr`**

Although the bug can be found, it requires manually specify the input string length, which is
not very useful in this case.

**`signedint.c` on `klee`**
```
KLEE: done: explored paths = 102
KLEE: done: avg. constructs per query = 5
KLEE: done: total queries = 111
KLEE: done: valid queries = 1
KLEE: done: invalid queries = 110
KLEE: done: query cex = 111

KLEE: done: total instructions = 139442
KLEE: done: completed paths = 102
KLEE: done: generated tests = 102
KLEE: ERROR: /home/student/cs5231/KLEE/klee-uclibc/libc/string/strcpy.c:27: memory error: out of bound pointer
```

**`signedint.c` on `fuzzBALL`**
Was unable to find the bug due to a long process time. Optimizations such as starting from a specific address were
used, but with no avail. However, should we be given enough time, we should be able to find the bug.


##observations

**`gets.c` on `angr`**

**`gets.c` on `klee`**
```
KLEE: done: explored paths = 33
KLEE: done: avg. constructs per query = 16
KLEE: done: total queries = 22
KLEE: done: valid queries = 1
KLEE: done: invalid queries = 21
KLEE: done: query cex = 22

KLEE: done: total instructions = 29408
KLEE: done: completed paths = 33
KLEE: done: generated tests = 31
KLEE: ERROR: /home/student/cs5231/KLEE/klee-uclibc/libc/stdio/gets.c:28: memory error: out of bound pointer

```

**`gets.c` on `fuzzball`**


##observations

**`doublefree.c` on angr**

**`doublefree.c` on klee**
```
KLEE: done: explored paths = 29
KLEE: done: avg. constructs per query = 59
KLEE: done: total queries = 60
KLEE: done: valid queries = 25
KLEE: done: invalid queries = 35
KLEE: done: query cex = 60

KLEE: done: total instructions = 16878
KLEE: done: completed paths = 29
KLEE: done: generated tests = 26

KLEE: ERROR: /home/student/Desktop/benchmarks/scripts/../doublefree.c:17: memory error: invalid pointer: free
```

**`doublefree.c` on fuzzball**


**`unsignedint.c` on `fuzzball`**

