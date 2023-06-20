package main

import (
	"fmt"
	"time"

	"github.com/jschwinger233/bpf_k2u_benchmark/bpf"

	"github.com/cilium/ebpf"
)

func main() {
	progs := bpf.LoadProgram()
	data := make([]byte, 256)
	ctx := make([]byte, 256)
	for _, prog := range progs {
		start := time.Now()
		_, _, _, err := runBpfProgram(prog, data, ctx)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s: %v\n", prog.String(), time.Since(start))
	}
}

func runBpfProgram(prog *ebpf.Program, data, ctx []byte) (statusCode uint32, dataOut, ctxOut []byte, err error) {
	dataOut = make([]byte, len(data))
	ctxOut = make([]byte, len(ctx))
	opts := &ebpf.RunOptions{
		Data:       data, // skb->data
		DataOut:    dataOut,
		Context:    ctx, // memcpy(skb, ctx, sizeof(skb))
		ContextOut: ctxOut,
		Repeat:     9999999,
	}
	ret, err := prog.Run(opts)
	return ret, opts.DataOut, ctxOut, err
}
