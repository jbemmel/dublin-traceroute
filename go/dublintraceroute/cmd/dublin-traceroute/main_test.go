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

func TestBranchTTL(t *testing.T) {
	r := &results.Results{Flows: map[uint16][]results.Probe{
		33434: {testProbe("192.0.2.1", 1, false), testProbe("192.0.2.1", 4, true)},
		33435: {testProbe("192.0.2.1", 1, false), testProbe("192.0.2.1", 5, true)},
	}}
	require.Equal(t, uint8(4), branchTTL(r, 30))
}

func TestMergeTargetResultsSharesPrefix(t *testing.T) {
	primary := &results.Results{Flows: map[uint16][]results.Probe{
		33434: {
			testProbe("192.0.2.1", 1, false),
			testProbe("192.0.2.1", 2, false),
			testProbe("192.0.2.1", 3, true),
		},
	}}
	secondary := &results.Results{Flows: map[uint16][]results.Probe{
		33434: {testProbe("192.0.2.2", 3, true)},
	}}

	require.NoError(t, mergeTargetResults(primary, secondary, 3))
	require.Len(t, primary.Flows, 2)
	merged := primary.Flows[33435]
	require.Len(t, merged, 3)
	require.Equal(t, uint8(1), merged[0].Sent.IP.TTL)
	require.Equal(t, "192.0.2.1", merged[0].Sent.IP.DstIP.String())
	require.Equal(t, uint8(3), merged[2].Sent.IP.TTL)
	require.Equal(t, "192.0.2.2", merged[2].Sent.IP.DstIP.String())
	require.True(t, merged[2].IsLast)
}
