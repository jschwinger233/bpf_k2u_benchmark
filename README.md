# bpf_k2u_benchmark

This repo aims to compare the latency / throughput characteristics of multiple [bpf-helpers(7)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html) for pushing kernel data to user space. The current matrix covers

- `bpf_perf_event_output`
- `bpf_ringbuf_output` in several production-like configurations (force wakeup, no wakeup, reserve submit, wakeup on no space, adaptive wakeup-on-no-space2)
- `bpf_map_push_elem` for `BPF_MAP_TYPE_QUEUE`

## Env

Most of my measurements use:

- Ubuntu 22.04, kernel 5.19.0-45-generic
- `go1.25.1` toolchain (module target remains 1.23 to keep backward compatibility)
- [`github.com/cilium/ebpf`](https://github.com/cilium/ebpf) v0.19.0 (for modern perf / ringbuf readers)
- clang 19.0.0 (any recent clang should do as long as it can build `bpf2go` targets)

These versions can influence results, so please call out your environment if you report numbers.

## Test

Every run loads the tc programs defined in [`bpf/test.c`](./bpf/test.c) and executes each one **9,999,999** times via `bpf_prog_test_run_opts`. The only variation between programs is how an 80-byte `struct skb_meta` is presented to user space. The current set contains:

1. `perf_test` – `bpf_perf_event_output`
2. `ringbuf_wakeup_test` – ring buffer with `BPF_RB_FORCE_WAKEUP`
3. `ringbuf_nowakeup_test` – ring buffer with `BPF_RB_NO_WAKEUP`
4. `ringbuf_nowakeup_reserve_test` – reserve / submit path with `BPF_RB_NO_WAKEUP`
5. `ringbuf_wakeup_on_no_space_test` – attempts to reserve additional space and forces wakeup when the ring is almost full
6. `ringbuf_wakeup_on_no_space2_test` – tracks pending bytes in a map and flips to `BPF_RB_FORCE_WAKEUP` once `(1 << 19) / 2` bytes are outstanding
7. `queue_test` – `bpf_map_push_elem` on a `BPF_MAP_TYPE_QUEUE`

Command: `go generate ./... && go build . && sudo ./bpf_k2u_benchmark`

### Userspace reader

`main.go` spins a consumer per test using the cilium/ebpf readers:

- Perf: `perf.Reader` with per-CPU buffers and lost-sample accounting.
- Ringbuf: `ringbuf.Reader` with deadline handling and post-run statistics.
- Queue: `LookupAndDelete` loop on the queue map.

All readers count how many samples they receive, tolerate soft failures as warnings, and enforce that `received + lost == 9_999_999`. Ringbuf paths also read two kernel-provided stats:

1. `ringbuf_fail_stats` – per-program counters of `bpf_ringbuf_output` / `reserve` failures.
2. `ringbuf_pending_bytes` – used by `ringbuf_wakeup_on_no_space2_test` to decide when to switch from `NO_WAKEUP` to `FORCE_WAKEUP`.

After each test the benchmark prints elapsed wall time plus any recorded lost/missing events so you can tell whether gaps were due to user-space readers or kernel back pressure.

## Results

Please do not rely on the historic numbers from the early version of this repo (the environment, helpers, and even readers have changed significantly). Instead, run the command above on your target kernel and paste the full output (including the “lost” / “missing events” lines) when sharing results.

A few practical notes:

1. Each `meta_ringbuf*` map currently uses a relatively large size (`1 << 19`) so that `bpf_prog_test_run_opts` can execute without `EINVAL`. Adjust if your kernel allows smaller buffers.
2. When experimenting with `BPF_RB_NO_WAKEUP`, watch both the user-space lost counter and `ringbuf_fail_stats` – if the kernel can’t reserve slots fast enough you’ll see “missing events (ringbuf failures)” printed.
3. Enthusiastic developers continue to share numbers on the [issues page](https://github.com/jschwinger233/bpf_k2u_benchmark/issues); feel free to contribute your data (ideally noting OS, kernel, Go, clang, and hardware).
