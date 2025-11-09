// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct skb_meta {
	__u64	address;

	/* fetch 13 fields from skb */
	__u32	len;
	__u32	pkt_type;
	__u32	mark;
	__u32	queue_mapping;
	__u32	protocol;
	__u32	vlan_present;
	__u32	vlan_tci;
	__u32	vlan_proto;
	__u32	priority;
	__u32	ingress_ifindex;
	__u32	ifindex;
	__u32	tc_index;
	__u32	cb[5];
};

struct bpf_map_def SEC("maps") meta_queue = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(struct skb_meta),
	.max_entries = 1000000,
};

struct {
   __uint(type, BPF_MAP_TYPE_RINGBUF);
   __uint(max_entries, 1<<19);
} meta_ringbuf1 SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_RINGBUF);
   __uint(max_entries, 1<<19);
} meta_ringbuf2 SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_RINGBUF);
   __uint(max_entries, 1<<19);
} meta_ringbuf3 SEC(".maps");

#define RINGBUF_WAKEUP_THRESHOLD_BYTES ((1 << 19) / 2)

enum ringbuf_fail_idx {
	RINGBUF_FAIL_WAKEUP = 0,
	RINGBUF_FAIL_NOWAKEUP,
	RINGBUF_FAIL_RESERVE,
	RINGBUF_FAIL_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, RINGBUF_FAIL_MAX);
	__type(key, __u32);
	__type(value, __u64);
} ringbuf_fail_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} ringbuf_pending_bytes SEC(".maps");

static __always_inline void inc_ringbuf_fail(enum ringbuf_fail_idx idx)
{
	__u32 key = idx;
	__u64 *value = bpf_map_lookup_elem(&ringbuf_fail_stats, &key);
	if (value)
		__sync_fetch_and_add(value, 1);
}


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} meta_perf SEC(".maps");

SEC("tc")
int perf_test(struct __sk_buff *skb)
{
	struct skb_meta meta;
	__builtin_memset(&meta, 0, sizeof(meta));
	bpf_perf_event_output(skb, &meta_perf, BPF_F_CURRENT_CPU, &meta, sizeof(meta));
	return 0;
}

SEC("tc")
int ringbuf_wakeup_test(struct __sk_buff *skb)
{
	struct skb_meta meta;
	__builtin_memset(&meta, 0, sizeof(meta));
	long ret = bpf_ringbuf_output(&meta_ringbuf1, &meta, sizeof(meta), BPF_RB_FORCE_WAKEUP);
	if (ret)
		inc_ringbuf_fail(RINGBUF_FAIL_WAKEUP);
	return 0;
}

SEC("tc")
int ringbuf_nowakeup_test(struct __sk_buff *skb)
{
	struct skb_meta meta;
	__builtin_memset(&meta, 0, sizeof(meta));
	long ret = bpf_ringbuf_output(&meta_ringbuf2, &meta, sizeof(meta), BPF_RB_NO_WAKEUP);
	if (ret)
		inc_ringbuf_fail(RINGBUF_FAIL_NOWAKEUP);
	return 0;
}

SEC("tc")
int ringbuf_nowakeup_reserve_test(struct __sk_buff *skb)
{
	struct skb_meta *meta;
	meta = bpf_ringbuf_reserve(&meta_ringbuf3, sizeof(struct skb_meta), 0);
	if (!meta) {
		inc_ringbuf_fail(RINGBUF_FAIL_RESERVE);
		return 0;
	}
	__builtin_memset(meta, 0, sizeof(*meta));
	bpf_ringbuf_submit(meta, BPF_RB_NO_WAKEUP);
	return 0;
}

SEC("tc")
int ringbuf_wakeup_on_no_space_test(struct __sk_buff *skb)
{
	struct skb_meta *meta;
	meta = bpf_ringbuf_reserve(&meta_ringbuf3, sizeof(struct skb_meta), 0);
	if (!meta) {
		inc_ringbuf_fail(RINGBUF_FAIL_RESERVE);
		return 0;
	}
	__builtin_memset(meta, 0, sizeof(*meta));
	u64 flags = BPF_RB_NO_WAKEUP;
	void *test = bpf_ringbuf_reserve(&meta_ringbuf3, RINGBUF_WAKEUP_THRESHOLD_BYTES, 0);
	if (!test)
		flags = BPF_RB_FORCE_WAKEUP;
	else
		bpf_ringbuf_discard(test, 0);
	bpf_ringbuf_submit(meta, flags);
	return 0;
}

SEC("tc")
int ringbuf_wakeup_on_no_space2_test(struct __sk_buff *skb)
{
	struct skb_meta *meta;
	__u32 key = 0;
	__u64 *pending;
	meta = bpf_ringbuf_reserve(&meta_ringbuf3, sizeof(struct skb_meta), 0);
	if (!meta) {
		inc_ringbuf_fail(RINGBUF_FAIL_RESERVE);
		return 0;
	}
	__builtin_memset(meta, 0, sizeof(*meta));
	__u64 flags = 0;
	pending = bpf_map_lookup_elem(&ringbuf_pending_bytes, &key);
	if (pending) {
		__sync_fetch_and_add(pending, sizeof(*meta));
		if (*pending >= RINGBUF_WAKEUP_THRESHOLD_BYTES) {
			flags = BPF_RB_FORCE_WAKEUP;
			__sync_lock_test_and_set(pending, 0);
		}
	}
	bpf_ringbuf_submit(meta, flags);
	return 0;
}

SEC("tc")
int queue_test(struct __sk_buff *skb)
{
	struct skb_meta meta;
	__builtin_memset(&meta, 0, sizeof(meta));
	bpf_map_push_elem(&meta_queue, &meta, BPF_EXIST);
	return 0;
}
