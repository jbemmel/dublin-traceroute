/* SPDX-License-Identifier: BSD-2-Clause */

package main

import (
	"net"
	"testing"

	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/results"
	"github.com/stretchr/testify/require"
)

func testProbe(target string, ttl uint8, last bool) results.Probe {
	return results.Probe{
		IsLast: last,
		Sent: results.Packet{IP: results.IP{
			DstIP: net.ParseIP(target),
			TTL:   ttl,
		}},
	}
}

func TestResolveTargets(t *testing.T) {
	targets, err := resolveTargets("192.0.2.1, 192.0.2.2,192.0.2.1", false)
	require.NoError(t, err)
	require.Equal(t, []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}, targets)
}

func TestResolveTargetsRejectsEmptyEntry(t *testing.T) {
	_, err := resolveTargets("192.0.2.1,", false)
	require.EqualError(t, err, "target list contains an empty target")
}

func TestMergeTargetResultsKeepsPathsIndependent(t *testing.T) {
	primaryFlow := []results.Probe{
		testProbe("192.0.2.1", 1, false),
		testProbe("192.0.2.1", 2, false),
		testProbe("192.0.2.1", 3, true),
	}
	primary := &results.Results{Flows: map[uint16][]results.Probe{33434: primaryFlow}}
	// Reuse the same flow ID across three destinations with different path lengths.
	for i, target := range []string{"192.0.2.2", "192.0.2.3"} {
		flow := []results.Probe{
			testProbe(target, 1, false),
			testProbe(target, 2, i == 0),
		}
		if i == 1 {
			flow = append(flow, testProbe(target, 3, false), testProbe(target, 4, true))
		}
		secondary := &results.Results{Flows: map[uint16][]results.Probe{33434: flow}}
		require.NoError(t, mergeTargetResults(primary, secondary))
		require.Equal(t, flow, primary.Flows[uint16(33435+i)])
		require.Equal(t, flow, secondary.Flows[33434])
	}
	require.Len(t, primary.Flows, 3)
	require.Equal(t, primaryFlow, primary.Flows[33434])
}
