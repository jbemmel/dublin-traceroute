/* SPDX-License-Identifier: BSD-2-Clause */

package main

import (
	"errors"
	"fmt"
	"go/build"
	"log"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute"
	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/probes/probev4"
	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/probes/probev6"
	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/results"
)

// Program constants and default values
const (
	ProgramName         = "Dublin Traceroute"
	ProgramVersion      = "v0.2"
	ProgramAuthorName   = "Andrea Barberio"
	ProgramAuthorInfo   = "https://insomniac.slackware.it"
	DefaultSourcePort   = 12345
	DefaultDestPort     = 33434
	DefaultNumPaths     = 10
	DefaultMinTTL       = 1
	DefaultMaxTTL       = 30
	DefaultDelay        = 50 //msec
	DefaultReadTimeout  = 3 * time.Second
	DefaultOutputFormat = "json"
)

// used to hold flags
type args struct {
	version      bool
	target       string
	sport        int
	useSrcport   bool
	dport        int
	npaths       int
	minTTL       int
	maxTTL       int
	delay        int
	brokenNAT    bool
	outputFile   string
	outputFormat string
	v4           bool
}

func resolveTargets(value string, wantV6 bool) ([]net.IP, error) {
	parts := strings.Split(value, ",")
	targets := make([]net.IP, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		host := strings.TrimSpace(part)
		if host == "" {
			return nil, errors.New("target list contains an empty target")
		}
		ip, err := resolve(host, wantV6)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve %s: %w", host, err)
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, ip)
	}
	return targets, nil
}

// branchTTL returns the first TTL at which the reference target answered. All
// earlier probes form the prefix that can be shared with the other targets.
func branchTTL(r *results.Results, fallback uint8) uint8 {
	branch := fallback
	for _, flow := range r.Flows {
		for _, probe := range flow {
			if probe.IsLast && probe.Sent.IP.TTL < branch {
				branch = probe.Sent.IP.TTL
				break
			}
		}
	}
	return branch
}

func mergeTargetResults(dst, src *results.Results, branch uint8) error {
	ids := make([]int, 0, len(src.Flows))
	for id := range src.Flows {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)

	next := 0
	for id := range dst.Flows {
		if int(id) >= next {
			next = int(id) + 1
		}
	}
	for _, rawID := range ids {
		if next > 0xffff {
			return errors.New("too many target paths to represent in the result")
		}
		id := uint16(rawID)
		flow := make([]results.Probe, 0, len(dst.Flows[id])+len(src.Flows[id]))
		for _, probe := range dst.Flows[id] {
			if probe.Sent.IP.TTL >= branch {
				break
			}
			probe.IsLast = false
			flow = append(flow, probe)
		}
		flow = append(flow, src.Flows[id]...)
		dst.Flows[uint16(next)] = flow
		next++
	}
	return nil
}

// Args will hold the program arguments
var Args args

// resolve returns the first IP address for the given host. If `wantV6` is true,
// it will return the first IPv6 address, or nil if none. Similarly for IPv4
// when `wantV6` is false.
// If the host is already an IP address, such IP address will be returned. If
// `wantV6` is true but no IPv6 address is found, it will return an error.
// Similarly for IPv4 when `wantV6` is false.
func resolve(host string, wantV6 bool) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if wantV6 && ip.To4() != nil {
			return nil, errors.New("Wanted an IPv6 address but got an IPv4 address")
		} else if !wantV6 && ip.To4() == nil {
			return nil, errors.New("Wanted an IPv4 address but got an IPv6 address")
		}
		return ip, nil
	}
	ipaddrs, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	var ret net.IP
	for _, ipaddr := range ipaddrs {
		if wantV6 && ipaddr.To4() == nil {
			ret = ipaddr
			break
		} else if !wantV6 && ipaddr.To4() != nil {
			ret = ipaddr
		}
	}
	if ret == nil {
		return nil, errors.New("No IP address of the requested type was found")
	}
	return ret, nil
}

func init() {
	// Ensure that CGO is disabled
	var ctx build.Context
	if ctx.CgoEnabled {
		fmt.Println("Disabling CGo")
		ctx.CgoEnabled = false
	}

	// handle flags
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Dublin Traceroute (Go implementation) %s\n", ProgramVersion)
		fmt.Fprintf(os.Stderr, "Written by %s - %s\n", ProgramAuthorName, ProgramAuthorInfo)
		fmt.Fprintf(os.Stderr, "\nUsage: dublin-traceroute [options] <target>[,<target>...]\n\n")
		flag.PrintDefaults()
	}
	// Args holds the program's arguments as parsed by `flag`
	flag.BoolVarP(&Args.version, "version", "v", false, "print the version of Dublin Traceroute")
	flag.IntVarP(&Args.sport, "sport", "s", DefaultSourcePort, "the source port to send packets from")
	flag.IntVarP(&Args.dport, "dport", "d", DefaultDestPort, "the base destination port to send packets to")
	flag.IntVarP(&Args.npaths, "npaths", "n", DefaultNumPaths, "the number of paths to probe")
	flag.IntVarP(&Args.minTTL, "min-ttl", "t", DefaultMinTTL, "the minimum TTL to probe")
	flag.IntVarP(&Args.maxTTL, "max-ttl", "T", DefaultMaxTTL, "the maximum TTL to probe")
	flag.IntVarP(&Args.delay, "delay", "D", DefaultDelay, "the inter-packet delay in milliseconds")
	flag.BoolVarP(&Args.brokenNAT, "broken-nat", "b", false, "the network has a broken NAT configuration (e.g. no payload fixup). Try this if you see fewer hops than expected")
	flag.BoolVarP(&Args.useSrcport, "use-srcport", "i", false, "generate paths using source port instead of destination port")
	flag.StringVarP(&Args.outputFile, "output-file", "o", "", "the output file name. If unspecified, or \"-\", print to stdout")
	flag.StringVarP(&Args.outputFormat, "output-format", "f", DefaultOutputFormat, "the output file format, either \"json\" or \"dot\"")
	flag.BoolVarP(&Args.v4, "force-ipv4", "4", false, "Force the use of the legacy IPv4 protocol")
	flag.CommandLine.SortFlags = false
}

func main() {
	SetColourPurple := "\x1b[0;35m"
	UnsetColour := "\x1b[0m"
	if os.Geteuid() == 0 {
		if runtime.GOOS == "linux" {
			fmt.Fprintf(os.Stderr, "%sWARNING: you are running this program as root. Consider setting the CAP_NET_RAW capability and running as non-root user as a more secure alternative%s\n", SetColourPurple, UnsetColour)
		}
	}

	flag.Parse()
	if Args.version {
		fmt.Printf("%v %v\n", ProgramName, ProgramVersion)
		os.Exit(0)
	}

	if len(flag.Args()) != 1 {
		log.Fatal("Exactly one target argument is required (use commas for multiple targets)")
	}

	Args.target = flag.Arg(0)
	targets, err := resolveTargets(Args.target, !Args.v4)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "Traceroute configuration:\n")
	fmt.Fprintf(os.Stderr, "Targets               : %v\n", targets)
	fmt.Fprintf(os.Stderr, "Base source port      : %v\n", Args.sport)
	fmt.Fprintf(os.Stderr, "Base destination port : %v\n", Args.dport)
	fmt.Fprintf(os.Stderr, "Use srcport for paths : %v\n", Args.useSrcport)
	fmt.Fprintf(os.Stderr, "Number of paths       : %v\n", Args.npaths)
	fmt.Fprintf(os.Stderr, "Minimum TTL           : %v\n", Args.minTTL)
	fmt.Fprintf(os.Stderr, "Maximum TTL           : %v\n", Args.maxTTL)
	fmt.Fprintf(os.Stderr, "Inter-packet delay    : %v\n", Args.delay)
	fmt.Fprintf(os.Stderr, "Timeout               : %v\n", time.Duration(Args.delay)*time.Millisecond)
	fmt.Fprintf(os.Stderr, "Treat as broken NAT   : %v\n", Args.brokenNAT)

	newTraceroute := func(target net.IP, minTTL, maxTTL uint8) dublintraceroute.DublinTraceroute {
		if Args.v4 {
			return &probev4.UDPv4{
				Target:     target,
				SrcPort:    uint16(Args.sport),
				DstPort:    uint16(Args.dport),
				UseSrcPort: Args.useSrcport,
				NumPaths:   uint16(Args.npaths),
				MinTTL:     minTTL,
				MaxTTL:     maxTTL,
				Delay:      time.Duration(Args.delay) * time.Millisecond,
				Timeout:    DefaultReadTimeout,
				BrokenNAT:  Args.brokenNAT,
			}
		}
		return &probev6.UDPv6{
			Target:      target,
			SrcPort:     uint16(Args.sport),
			DstPort:     uint16(Args.dport),
			UseSrcPort:  Args.useSrcport,
			NumPaths:    uint16(Args.npaths),
			MinHopLimit: minTTL,
			MaxHopLimit: maxTTL,
			Delay:       time.Duration(Args.delay) * time.Millisecond,
			Timeout:     DefaultReadTimeout,
			BrokenNAT:   Args.brokenNAT,
		}
	}
	traceResults, err := newTraceroute(targets[0], uint8(Args.minTTL), uint8(Args.maxTTL)).Traceroute()
	if err != nil {
		log.Fatalf("Traceroute() failed: %v", err)
	}
	if len(targets) > 1 {
		branch := branchTTL(traceResults, uint8(Args.maxTTL))
		fmt.Fprintf(os.Stderr, "Target fan-out TTL    : %v\n", branch)
		for _, target := range targets[1:] {
			targetResults, traceErr := newTraceroute(target, branch, branch).Traceroute()
			if traceErr != nil {
				log.Fatalf("Traceroute() to %s failed: %v", target, traceErr)
			}
			if err := mergeTargetResults(traceResults, targetResults, branch); err != nil {
				log.Fatalf("Cannot merge results for %s: %v", target, err)
			}
		}
	}
	var (
		output string
	)
	switch Args.outputFormat {
	case "json":
		output, err = traceResults.ToJSON(true, "  ")
	case "dot":
		output, err = traceResults.ToDOT()
	default:
		log.Fatalf("Unknown output format \"%s\"", Args.outputFormat)
	}
	if err != nil {
		log.Fatalf("Failed to generate output in format \"%s\": %v", Args.outputFormat, err)
	}
	if Args.outputFile == "-" || Args.outputFile == "" {
		fmt.Println(output)
	} else {
		err := os.WriteFile(Args.outputFile, []byte(output), 0644)
		if err != nil {
			log.Fatalf("Failed to write to file: %v", err)
		}
		log.Printf("Saved results to to \"%s\"", Args.outputFile)
		if Args.outputFormat == "json" {
			log.Printf("You can convert it to DOT by running `todot \"%s\" -o \"%s.dot\"`", Args.outputFile, Args.outputFile)
		}
		log.Printf("You can convert the DOT file to PNG by running `dot -Tpng \"%s.dot\" -o \"%s.png\"`", Args.outputFile, Args.outputFile)
	}
}
