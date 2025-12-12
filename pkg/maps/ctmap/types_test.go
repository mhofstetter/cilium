// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapKey(t *testing.T) {
	for mapType := mapType(0); mapType < mapTypeMax; mapType++ {
		assert.NotNil(t, mapType.key())
	}

	assert.Panics(t, func() { mapType(-1).key() })
	assert.Panics(t, func() { mapTypeMax.key() })
}
