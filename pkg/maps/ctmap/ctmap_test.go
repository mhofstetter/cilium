// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func init() {
	InitMapInfo(nil, true, true, true)
}

func TestFilterMapsByProto(t *testing.T) {
	maps := []*Map{
		newMap("tcp4", mapTypeIPv4TCPGlobal, nil),
		newMap("any4", mapTypeIPv4AnyGlobal, nil),
		newMap("tcp6", mapTypeIPv6TCPGlobal, nil),
		newMap("any6", mapTypeIPv6AnyGlobal, nil),
	}

	ctMapTCP, ctMapAny := FilterMapsByProto(maps, CTMapIPv4)
	require.Equal(t, mapTypeIPv4TCPGlobal, ctMapTCP.mapType)
	require.Equal(t, mapTypeIPv4AnyGlobal, ctMapAny.mapType)

	ctMapTCP, ctMapAny = FilterMapsByProto(maps, CTMapIPv6)
	require.Equal(t, mapTypeIPv6TCPGlobal, ctMapTCP.mapType)
	require.Equal(t, mapTypeIPv6AnyGlobal, ctMapAny.mapType)

	maps = maps[0:2] // remove ipv6 maps
	ctMapTCP, ctMapAny = FilterMapsByProto(maps, CTMapIPv6)
	require.Nil(t, ctMapTCP)
	require.Nil(t, ctMapAny)
}
