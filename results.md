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


> <Explorer with paths: 2 active, 0 spilled, 23 deadended, 2799 errored, 0 unconstrained, 0 found, 0 avoided, 0 deviating, 0 looping, 0 lost>

23 paths exited normally. 2799 paths errored out. `angr` kept running
(generating more errored paths) until manually interuption.
