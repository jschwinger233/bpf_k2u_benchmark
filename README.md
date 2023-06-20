# bpf_k2u_benchmark

This repo aims to compare performance among three [bpf-helpers(7)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html) functions pushing kernel data to userpsace: `bpf_perf_event_output`, `bpf_ringbuf_output`, `bpf_map_push_elem` for `BPF_MAP_TYPE_QUEUE`.

## Env

My OS is Ubuntu-22.04, 5.19.0-45-generic; go compiler is go1.20 linux/amd64; eBPF library is cilium/ebpf@v0.10.0; clang is of version 14.0.0-1ubuntu1.

Above versions (and eBPF library) could matter to the results, I'm happy to receive feedback if one find any significant difference on other platform.

## Test

The benchmark is done by running 4 pieces of tc bpf programs with 9999999 times repeat, the only differences among these bpf programs are the way to submit an 80-byte struct from kernel to userspace. You can find this [here](https://github.com/jschwinger233/bpf_k2u_benchmark/blob/main/bpf/test.c).

Command: `go generate ./... && go build . && sudo ./bpf_k2u_benchmark`

## Results

My results showed `bpf_perf_event_output` outspeeds the other two functions, and `bpf_map_push_elem` works faster than `bpf_ringbuf_output`:

```
SchedCLS(perf_test)#8: 81.285475ms
SchedCLS(ringbuf_wakeup_test)#14: 1.821359149s
SchedCLS(ringbuf_nowakeup_test)#12: 198.32416ms
SchedCLS(queue_test)#10: 166.39498ms
```

Something to point out:

1\. In the repo we don't have any userspace program to pull data, so events will be dropped when the kernel buffer is gradually filled up. This might not be the real world running situation because there suppose to be a userspace process consuming events all the time.

2\. Ringbuf is initialized using the following code:
```c
struct {
   __uint(type, BPF_MAP_TYPE_RINGBUF);
   __uint(max_entries, 1<<29);
} meta_ringbuf1 SEC(".maps");
```
The `1<<29` looks suspicious but I find it necessary, or I'll get an error: `panic: field RingbufWakeupTest: program ringbuf_wakeup_test: map meta_ringbuf1: map create: invalid argument (without BTF k/v)`

3\. Enthusiastic developers provided their test results on the [issues page](https://github.com/jschwinger233/bpf_k2u_benchmark/issues). The majority of test results showed ringbuf still has perf-advantages over bpf queue, although not huge, but still obvious.
