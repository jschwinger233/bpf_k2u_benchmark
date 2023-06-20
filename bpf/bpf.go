package bpf

import "github.com/cilium/ebpf"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native Test ./test.c -- -I./headers -I. -Wall

func LoadProgram() []*ebpf.Program {
	obj := &TestObjects{}
	if err := LoadTestObjects(obj, nil); err != nil {
		panic(err)
	}
	return []*ebpf.Program{obj.PerfTest, obj.RingbufWakeupTest, obj.RingbufNowakeupTest, obj.QueueTest}
}
