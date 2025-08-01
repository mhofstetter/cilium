// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedRemoveOldRouterState(t *testing.T) {
	testutils.PrivilegedTest(t)

	t.Run("test-1", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			createDevices(t)

			// Assert that the old router IP (192.0.2.1) was removed because we are
			// restoring a different one (10.0.0.1).
			assert.NoError(t, removeOldRouterState(hivetest.Logger(t), false, net.ParseIP("10.0.0.1")))
			addrs, err := netlink.AddrList(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: defaults.HostDevice,
				},
			}, netlink.FAMILY_V4)
			assert.NoError(t, err)
			assert.Empty(t, addrs)

			// Assert no errors in the case we have no IPs to remove from cilium_host.
			assert.NoError(t, removeOldRouterState(hivetest.Logger(t), false, nil))

			return nil
		})
	})

	t.Run("test-2", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			createDevices(t)

			// Remove the cilium_host device and assert no error on "link not found"
			// error.
			link, err := safenetlink.LinkByName(defaults.HostDevice)
			assert.NoError(t, err)
			assert.NotNil(t, link)
			assert.NoError(t, netlink.LinkDel(link))
			assert.NoError(t, removeOldRouterState(hivetest.Logger(t), false, nil))

			return nil
		})
	})
}

// createDevices creates the necessary devices for this test suite. Assumes it
// is executing within the new network namespace.
func createDevices(t *testing.T) {
	t.Helper()

	hostMac, err := mac.GenerateRandMAC()
	if err != nil {
		assert.NoError(t, err)
	}
	veth := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:         defaults.HostDevice,
			HardwareAddr: net.HardwareAddr(hostMac),
			TxQLen:       1000,
		},
	}
	if err := netlink.LinkAdd(veth); err != nil {
		assert.NoError(t, err)
	}
	ciliumHost, err := safenetlink.LinkByName(defaults.HostDevice)
	if err != nil {
		assert.NoError(t, err)
	}

	_, ipnet, _ := net.ParseCIDR("192.0.2.1/32")
	addr := &netlink.Addr{IPNet: ipnet}
	assert.NoError(t, netlink.AddrAdd(ciliumHost, addr))
}

func TestPrivilegedRemoveStaleEPIfaces(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		linkAttrs := netlink.NewLinkAttrs()
		linkAttrs.Name = "lxc12345"
		veth := &netlink.Veth{
			LinkAttrs: linkAttrs,
			PeerName:  "tmp54321",
		}

		err := netlink.LinkAdd(veth)
		assert.NoError(t, err)

		_, err = safenetlink.LinkByName(linkAttrs.Name)
		assert.NoError(t, err)

		// Check that stale iface is removed
		err = clearCiliumVeths(hivetest.Logger(t))
		assert.NoError(t, err)

		_, err = safenetlink.LinkByName(linkAttrs.Name)
		assert.Error(t, err)

		return nil
	})
}
