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

## Observations

**`array.c` on `angr`**


```
<Explorer with paths: 2 active, 0 spilled, 23 deadended, 2799 errored, 0 unconstrained, 0 found, 0 avoided, 0 deviating, 0 looping, 0 lost>
```

23 paths exited normally. 2799 paths errored out. `angr` kept running
(generating more errored paths) until manually interuption.

**`array.c` on `klee`**
```
KLEE: done: explored paths = 11457
KLEE: done: avg. constructs per query = 100
KLEE: done: total queries = 6286
KLEE: done: valid queries = 4628
KLEE: done: invalid queries = 1658
KLEE: done: query cex = 6286

KLEE: done: total instructions = 744926
KLEE: done: completed paths = 11457
KLEE: done: generated tests = 4
KLEE: done: generated failing tests = 2
KLEE: ERROR: /home/student/cs5231/KLEE/klee-uclibc/libc/stdlib/stdlib.c:526: memory error: out of bound pointer
KLEE: ERROR: /home/student/Desktop/benchmarks/array_vul/array.c:16: memory error: out of bound pointer
```
 `klee` kept running until time-out of 360 seconds

### `strcpy.c`

This is a simple demonstration of memory out-of-bound error. 
The program will accept one argument as a string.  Memory out-of-bound error
will be triggered when the number of characters in the string is more than 10.

##observations

**`strcpy.c` on `angr`**

**`strcpy.c` on `klee`**
```
KLEE: done: explored paths = 18
KLEE: done: avg. constructs per query = 39
KLEE: done: total queries = 209
KLEE: done: valid queries = 3
KLEE: done: invalid queries = 206
KLEE: done: query cex = 209

KLEE: done: total instructions = 27932
KLEE: done: completed paths = 18
KLEE: done: generated tests = 2
KLEE: done: generated failing tests = 1
KLEE: ERROR: /home/student/cs5231/KLEE/klee-uclibc/libc/string/strcpy.c:27: memory error: out of bound pointer
```

**`strcpy.c` on `fuzzball`**

### signedint.c

This is a simple demonstration of an signed int vulnerability.
The check for the length of the argument will pass when the length of
the arugment provided is so long such that it resulted in an integer
overflow (looping back to negative value). This will cause strcpy to copy
an input with length more than the size of the allocated buffer, resulting
in an memory out-of-point error

##observations

**`unsignedint.c` on `angr`**

**`unsignedint.c` on `klee`**
```
KLEE: done: explored paths = 108
KLEE: done: avg. constructs per query = 28
KLEE: done: total queries = 299
KLEE: done: valid queries = 3
KLEE: done: invalid queries = 296
KLEE: done: query cex = 299

KLEE: done: total instructions = 156197
KLEE: done: completed paths = 108
KLEE: done: generated tests = 2
KLEE: done: generated failing tests = 1
KLEE: ERROR: /home/student/cs5231/KLEE/klee-uclibc/libc/string/strcpy.c:27: memory error: out of bound pointer
```

###`gets.c`
This is a simple demonstration of how gets did not check for the 
length of the input. An input with length more than 10 will trigger
a memory out-of-bounds error

##onservations

**`unsignedint.c` on `angr`**

**`unsignedint.c` on `klee`**
```
KLEE: done: explored paths = 22
KLEE: done: avg. constructs per query = 43
KLEE: done: total queries = 224
KLEE: done: valid queries = 1
KLEE: done: invalid queries = 223
KLEE: done: query cex = 224

KLEE: done: total instructions = 22093
KLEE: done: completed paths = 22
KLEE: done: generated tests = 3
KLEE: done: generated failing tests = 2
KLEE: ERROR: /home/student/cs5231/KLEE/klee-uclibc/libc/stdio/gets.c:28: memory error: out of bound pointer
KLEE: ERROR: /home/student/cs5231/KLEE/klee-uclibc/libc/stdio/gets.c:28: memory error: out of bound pointer
```

**`unsignedint.c` on `fuzzball`**




**`unsignedint.c` on `fuzzball`**
