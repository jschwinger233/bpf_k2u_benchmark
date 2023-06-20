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
   __uint(max_entries, 1<<29);
} meta_ringbuf1 SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_RINGBUF);
   __uint(max_entries, 1<<29);
} meta_ringbuf2 SEC(".maps");


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
	bpf_ringbuf_output(&meta_ringbuf1, &meta, sizeof(meta), BPF_RB_FORCE_WAKEUP);
	return 0;
}

SEC("tc")
int ringbuf_nowakeup_test(struct __sk_buff *skb)
{
	struct skb_meta meta;
	__builtin_memset(&meta, 0, sizeof(meta));
	bpf_ringbuf_output(&meta_ringbuf2, &meta, sizeof(meta), BPF_RB_NO_WAKEUP);
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
