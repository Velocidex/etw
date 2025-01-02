//go:build windows
// +build windows

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	_ "net/http/pprof"

	"github.com/Velocidex/etw"
	"golang.org/x/sys/windows"
)

var (
	optSilent  = flag.Bool("silent", false, "Stop sending logs to stderr")
	optSession = flag.String("session", "etw-test", "Session Name")
	optTimeout = flag.Int("timeout", 5, "Capture only for this timeout")
	optID      = flag.Int("id", -1, "Capture only specified ID")
	optEvents  = flag.String("events", "registry,process", "Any of these separated by ,: registry,process,image_load,network,driver,file")
	optStacks  = flag.String("stack", "", "To enable stack traces for these event types: Any of these separated by ,: registry,process,image_load,network,driver,file")
	optProfile = flag.Int("profile", 0, "Enable profile server on this port")

	optKernelEventTypeFilter = flag.String("kernel_event_type_filter", ".", "Filter event types")
)

var count uint64

func main() {
	flag.Parse()

	if *optSilent {
		log.SetOutput(ioutil.Discard)
	}

	if *optProfile > 0 {
		go func() {
			log.Println(http.ListenAndServe(
				fmt.Sprintf("localhost:%v", *optProfile), nil))
		}()
	}

	event_type_filter, err := regexp.Compile(*optKernelEventTypeFilter)
	if err != nil {
		log.Fatalf("kernel_event_type_filter regex invalid: %v\n", *optKernelEventTypeFilter)
	}

	// Trap cancellation (the only signal values guaranteed to be present in
	// the os package on all systems are os.Interrupt and os.Kill).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-sigCh
		cancel()
	}()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	cb := func(e *etw.Event) {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if *optID > 0 && *optID != int(e.Header.ID) {
			return
		}

		out := e.Parsed()

		if event_type_filter.MatchString(e.Header.KernelLoggerType.String()) {
			etw.GetLazyProperty(e, "Backtrace")
			_ = enc.Encode(out)
			atomic.AddUint64(&count, 1)
		}
	}
	session, err := NewSession(flag.Arg(0), *optSession, cb)
	if err != nil {
		log.Fatalf("Failed to create etw session; %s", err)
		return
	}
	defer session.Close()

	for _, arg := range flag.Args() {
		guid, err := windows.GUIDFromString(arg)
		if err != nil {
			log.Fatalf("Incorrect GUID given; %s", err)
		}

		opts := etw.SessionOptions{
			Guid:          guid,
			Level:         etw.TraceLevel(255),
			CaptureState:  true,
			EnableMapInfo: false,
		}
		err = session.SubscribeToProvider(opts)
		log.Printf("[DBG] SubscribeToProvider %v\n", err)

		defer session.UnsubscribeFromProvider(guid)
	}

	go func() {
		defer cancel()

		log.Printf("[DBG] Starting to listen to ETW events")

		// Block until .Close().
		if err := session.Process(); err != nil {
			log.Printf("[ERR] Got error processing events: %s", err)
		} else {
			log.Printf("[DBG] Successfully shut down")
		}
	}()

	go func() {
		time.Sleep(time.Second * time.Duration(*optTimeout))
		log.Printf("[DBG] Closing session %v due to timeout with %v events received",
			*optSession, atomic.LoadUint64(&count))

		cancel()
	}()

	// Wait for stop and shutdown gracefully.
	<-ctx.Done()

	log.Printf("[DBG] Shutting the session down")
}

func NewSession(guid, name string, cb func(e *etw.Event)) (*etw.Session, error) {
	if strings.EqualFold(guid, etw.KernelTraceControlGUIDString) {
		opts, err := parseOpts(*optEvents)
		if err != nil {
			return nil, err
		}

		if *optStacks != "" {
			stack_opts, err := parseOpts(*optStacks)
			if err != nil {
				return nil, err
			}
			opts.StackTracing = stack_opts
		}

		session, err := etw.NewKernelTraceSession(*opts, cb)
		if err != nil {
			err = etw.KillSession(etw.KernelTraceSessionName)
			if err != nil {
				return nil, err
			}

			session, err = etw.NewKernelTraceSession(*opts, cb)
			if err != nil {
				return nil, err
			}
		}

		return session, nil
	}

	session, err := etw.NewSession(name, cb)
	if err != nil {
		err = etw.KillSession(name)
		if err != nil {
			return nil, err
		}

		session, err = etw.NewSession(name, cb)
		if err != nil {
			return nil, err
		}
	}

	return session, nil
}

func parseOpts(in string) (*etw.RundownOptions, error) {
	opts := &etw.RundownOptions{}

	for _, item := range strings.Split(in, ",") {
		err := opts.Set(item)
		if err != nil {
			return nil, err
		}
	}

	return opts, nil
}
