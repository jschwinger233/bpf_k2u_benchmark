package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/jschwinger233/bpf_k2u_benchmark/bpf"
)

const (
	totalEvents          = 6_999
	userspaceReadTimeout = 1 * time.Microsecond
	//userspaceReadTimeout   = 1 * time.Second
	ringbufWakeupFailIdx   = 0
	ringbufNoWakeupFailIdx = 1
	ringbufReserveFailIdx  = 2
	invalidStatIdx         = -1
)

type eventConsumer func(done <-chan struct{}, expected int) (received int, lost int, err error)

type benchCase struct {
	name    string
	prog    *ebpf.Program
	consume eventConsumer
	statIdx int
	preRun  func() error
}

type partialErr struct {
	received int
	lost     int
	expected int
	reason   string
}

func (e *partialErr) Error() string {
	return fmt.Sprintf("%s (accounted %d/%d events, lost %d)", e.reason, e.received+e.lost, e.expected, e.lost)
}

func newPartialErr(reason string, received, lost, expected int) error {
	return &partialErr{reason: reason, received: received, lost: lost, expected: expected}
}

func main() {
	obj := bpf.LoadProgram()
	defer obj.Close()

	data := make([]byte, 256)
	ctx := make([]byte, 256)

	perfBufSize := os.Getpagesize() * 256

	cases := []benchCase{
		{
			name:    fmt.Sprintf("%s/perf", obj.PerfTest.String()),
			prog:    obj.PerfTest,
			consume: newPerfConsumer(obj.MetaPerf, perfBufSize),
			statIdx: invalidStatIdx,
		},
		{
			name:    fmt.Sprintf("%s/ringbuf_force_wakeup", obj.RingbufWakeupTest.String()),
			prog:    obj.RingbufWakeupTest,
			consume: newRingbufConsumer(obj.MetaRingbuf1),
			statIdx: ringbufWakeupFailIdx,
		},
		{
			name:    fmt.Sprintf("%s/ringbuf_no_wakeup", obj.RingbufNowakeupTest.String()),
			prog:    obj.RingbufNowakeupTest,
			consume: newRingbufConsumer(obj.MetaRingbuf2),
			statIdx: ringbufNoWakeupFailIdx,
		},
		{
			name:    fmt.Sprintf("%s/ringbuf_no_wakeup_reserve", obj.RingbufNowakeupReserveTest.String()),
			prog:    obj.RingbufNowakeupReserveTest,
			consume: newRingbufConsumer(obj.MetaRingbuf3),
			statIdx: ringbufReserveFailIdx,
		},
		{
			name:    fmt.Sprintf("%s/ringbuf_wakeup_on_no_space", obj.RingbufWakeupOnNoSpaceTest.String()),
			prog:    obj.RingbufWakeupOnNoSpaceTest,
			consume: newRingbufConsumer(obj.MetaRingbuf3),
			statIdx: ringbufReserveFailIdx,
		},
		{
			name:    fmt.Sprintf("%s/ringbuf_wakeup_on_no_space2", obj.RingbufWakeupOnNoSpace2Test.String()),
			prog:    obj.RingbufWakeupOnNoSpace2Test,
			consume: newRingbufConsumer(obj.MetaRingbuf3),
			statIdx: ringbufReserveFailIdx,
			preRun: func() error {
				return resetPendingBytes(obj.RingbufPendingBytes)
			},
		},
		{
			name:    fmt.Sprintf("%s/queue", obj.QueueTest.String()),
			prog:    obj.QueueTest,
			consume: newQueueConsumer(obj.MetaQueue),
			statIdx: invalidStatIdx,
		},
	}

	var fatalErr bool
	for _, c := range cases {
		if c.preRun != nil {
			if err := c.preRun(); err != nil {
				log.Fatalf("%s pre-run setup failed: %v", c.name, err)
			}
		}
		if c.statIdx >= 0 {
			if obj.RingbufFailStats == nil {
				log.Fatalf("%s missing ringbuf failure stats map", c.name)
			}
			if err := resetRingbufFailures(obj.RingbufFailStats, uint32(c.statIdx)); err != nil {
				log.Fatalf("%s reset ringbuf stats: %v", c.name, err)
			}
		}
		duration, lost, err := runCase(c, data, ctx)
		if err != nil {
			if pe, ok := err.(*partialErr); ok {
				log.Printf("WARNING: %s %v", c.name, pe)
			} else {
				log.Printf("ERROR: %s failed: %v", c.name, err)
				fatalErr = true
			}
		}
		if lost > 0 {
			fmt.Printf("%s accounted for %d lost events\n", c.name, lost)
		}
		if c.statIdx >= 0 {
			missing, err := readRingbufFailures(obj.RingbufFailStats, uint32(c.statIdx))
			if err != nil {
				log.Printf("ERROR: %s ringbuf failure lookup: %v", c.name, err)
				fatalErr = true
			} else if missing > 0 {
				fmt.Printf("%s missing events (ringbuf failures): %d\n", c.name, missing)
			}
		}
		fmt.Printf("%s: %v\n", c.name, duration)
	}
	if fatalErr {
		os.Exit(1)
	}
}

func runCase(c benchCase, data, ctx []byte) (time.Duration, int, error) {
	start := time.Now()
	done := make(chan struct{})
	runErrCh := make(chan error, 1)

	go func() {
		defer close(done)
		_, _, _, err := runBpfProgram(c.prog, data, ctx)
		runErrCh <- err
	}()

	received, lost, consumeErr := c.consume(done, totalEvents)
	runErr := <-runErrCh
	duration := time.Since(start)

	if consumeErr != nil {
		return duration, lost, consumeErr
	}
	if runErr != nil {
		return duration, lost, runErr
	}
	if received+lost != totalEvents {
		return duration, lost, newPartialErr("userspace accounting mismatch", received, lost, totalEvents)
	}
	return duration, lost, nil
}

func newPerfConsumer(perfMap *ebpf.Map, perCPUBuffer int) eventConsumer {
	if perCPUBuffer <= 0 {
		perCPUBuffer = os.Getpagesize()
	}

	return func(done <-chan struct{}, expected int) (int, int, error) {
		reader, err := perf.NewReader(perfMap, perCPUBuffer)
		if err != nil {
			return 0, 0, fmt.Errorf("create perf reader: %w", err)
		}
		defer reader.Close()

		delivered := 0
		lost := 0
		total := 0
		for total < expected {
			reader.SetDeadline(time.Now().Add(userspaceReadTimeout))
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					if programFinished(done) {
						return delivered, lost, newPartialErr("perf reader finished early", delivered, lost, expected)
					}
					continue
				}
				if errors.Is(err, perf.ErrClosed) || errors.Is(err, perf.ErrFlushed) {
					continue
				}
				return delivered, lost, fmt.Errorf("perf read: %w", err)
			}

			lost += int(record.LostSamples)
			delivered++
			total++
		}

		return delivered, lost, nil
	}
}

func newRingbufConsumer(ringMap *ebpf.Map) eventConsumer {
	return func(done <-chan struct{}, expected int) (int, int, error) {
		reader, err := ringbuf.NewReader(ringMap)
		if err != nil {
			return 0, 0, fmt.Errorf("create ringbuf reader: %w", err)
		}
		defer reader.Close()

		received := 0
		for received < expected {
			reader.SetDeadline(time.Now().Add(userspaceReadTimeout))
			_, err := reader.Read()
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					if programFinished(done) {
						return received, 0, newPartialErr("ringbuf reader finished early", received, 0, expected)
					}
					continue
				}
				if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, ringbuf.ErrFlushed) {
					continue
				}
				return received, 0, fmt.Errorf("ringbuf read: %w", err)
			}
			received++
		}
		return received, 0, nil
	}
}

func newQueueConsumer(queueMap *ebpf.Map) eventConsumer {
	valueSize := int(queueMap.ValueSize())
	if valueSize <= 0 {
		return func(_ <-chan struct{}, _ int) (int, int, error) {
			return 0, 0, fmt.Errorf("queue map has invalid value size: %d", valueSize)
		}
	}

	return func(done <-chan struct{}, expected int) (int, int, error) {
		value := make([]byte, valueSize)
		received := 0
		for received < expected {
			if err := queueMap.LookupAndDelete(nil, value); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					if programFinished(done) {
						return received, 0, newPartialErr("queue drained early", received, 0, expected)
					}
					runtime.Gosched()
					continue
				}
				return received, 0, fmt.Errorf("queue read: %w", err)
			}
			received++
		}
		return received, 0, nil
	}
}

func programFinished(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func resetRingbufFailures(stats *ebpf.Map, idx uint32) error {
	zero := uint64(0)
	return stats.Update(&idx, &zero, ebpf.UpdateAny)
}

func readRingbufFailures(stats *ebpf.Map, idx uint32) (uint64, error) {
	var value uint64
	if err := stats.Lookup(&idx, &value); err != nil {
		return 0, err
	}
	return value, nil
}

func resetPendingBytes(m *ebpf.Map) error {
	if m == nil {
		return fmt.Errorf("ringbuf pending bytes map is nil")
	}
	var key uint32
	var zero uint64
	return m.Update(&key, &zero, ebpf.UpdateAny)
}

func runBpfProgram(prog *ebpf.Program, data, ctx []byte) (statusCode uint32, dataOut, ctxOut []byte, err error) {
	dataOut = make([]byte, len(data))
	ctxOut = make([]byte, len(ctx))
	opts := &ebpf.RunOptions{
		Data:       data,
		DataOut:    dataOut,
		Context:    ctx,
		ContextOut: ctxOut,
		Repeat:     totalEvents,
	}
	ret, err := prog.Run(opts)
	return ret, opts.DataOut, ctxOut, err
}
