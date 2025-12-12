package mapsize

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"

	"github.com/cilium/cilium/pkg/util"
)

const (
	_   = iota
	KiB = 1 << (10 * iota)
	MiB
	GiB
)

func TestCheckMapSizeLimits(t *testing.T) {
	type sizes struct {
		AuthMapEntries        int
		CTMapEntriesGlobalTCP int
		CTMapEntriesGlobalAny int
		NATMapEntriesGlobal   int
		FragmentsMapEntries   int
		NeighMapEntriesGlobal int
		WantErr               bool
	}
	tests := []struct {
		name string
		c    *bpfMapsSizeConfig
		want sizes
	}{
		{
			name: "default map sizes",
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:  false,
					BPFNATGlobalMax:    0,
					BPFNeighGlobalMax:  0,
					BPFCTGlobalTCPMax:  0,
					BPFCTGlobalAnyMax:  0,
					BPFAuthMapMax:      1 << 19,
					BPFFragmentsMapMax: 8192,
				},
				sizeofCTElement:      10,
				sizeofNATElement:     10,
				sizeofNeighElement:   10,
				sizeofSockRevElement: 10,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: 4294967, // calculated
				CTMapEntriesGlobalAny: 2147483, // calculated
				NATMapEntriesGlobal:   4294967, // calculated
				NeighMapEntriesGlobal: 4294967, // calculated
				AuthMapEntries:        1 << 19,
				FragmentsMapEntries:   8192,
				WantErr:               false,
			},
		},
		{
			name: "arbitrary map sizes within range",
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:  false,
					BPFNATGlobalMax:    2048,
					BPFNeighGlobalMax:  15000,
					BPFCTGlobalTCPMax:  20000,
					BPFCTGlobalAnyMax:  18000,
					BPFAuthMapMax:      20000,
					BPFFragmentsMapMax: 2 << 14,
				},
				sizeofCTElement:      10,
				sizeofNATElement:     10,
				sizeofNeighElement:   10,
				sizeofSockRevElement: 10,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: 20000,
				CTMapEntriesGlobalAny: 18000,
				NATMapEntriesGlobal:   2048,
				NeighMapEntriesGlobal: 15000,
				AuthMapEntries:        20000,
				FragmentsMapEntries:   2 << 14,
				WantErr:               false,
			},
		},
		{
			name: "CT TCP map size below range",
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFCTGlobalTCPMax: LimitTableMin - 1,
				},
				sizeofCTElement:      10,
				sizeofNATElement:     10,
				sizeofNeighElement:   10,
				sizeofSockRevElement: 10,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: LimitTableMin - 1,
				CTMapEntriesGlobalAny: 2147483,
				NATMapEntriesGlobal:   1432337,
				NeighMapEntriesGlobal: 1432337,
				WantErr:               true,
			},
		},
		{
			name: "CT TCP map size above range",
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFCTGlobalTCPMax: LimitTableMax + 1,
				},
				sizeofCTElement:      10,
				sizeofNATElement:     10,
				sizeofNeighElement:   10,
				sizeofSockRevElement: 10,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: LimitTableMax + 1,
				CTMapEntriesGlobalAny: 2147483,
				NATMapEntriesGlobal:   4294967,
				NeighMapEntriesGlobal: 4294967,
				WantErr:               true,
			},
		},
		{
			name: "CT Any map size below range",
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFCTGlobalAnyMax: LimitTableMin - 1,
				},
				sizeofCTElement:      10,
				sizeofNATElement:     10,
				sizeofNeighElement:   10,
				sizeofSockRevElement: 10,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: 4294967,
				CTMapEntriesGlobalAny: LimitTableMin - 1,
				NATMapEntriesGlobal:   4294967,
				NeighMapEntriesGlobal: 4294967,
				WantErr:               true,
			},
		},
		{
			name: "CT Any map size above range",
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFCTGlobalAnyMax: LimitTableMax + 1,
				},
				sizeofCTElement:      10,
				sizeofNATElement:     10,
				sizeofNeighElement:   10,
				sizeofSockRevElement: 10,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: 4294967,
				CTMapEntriesGlobalAny: LimitTableMax + 1,
				NATMapEntriesGlobal:   4294967,
				NeighMapEntriesGlobal: 4294967,
				WantErr:               true,
			},
		},
		{
			name: "NAT map size below range",
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFNATGlobalMax: LimitTableMin - 1,
				},
				sizeofCTElement:      10,
				sizeofNATElement:     10,
				sizeofNeighElement:   10,
				sizeofSockRevElement: 10,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: 4294967,
				CTMapEntriesGlobalAny: 2147483,
				NATMapEntriesGlobal:   LimitTableMin - 1,
				NeighMapEntriesGlobal: LimitTableMin - 1, // default to same size as NAT
				WantErr:               true,
			},
		},
		{
			name: "NAT map size above range",
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFNATGlobalMax: LimitTableMax + 1,
				},
				sizeofCTElement:      10,
				sizeofNATElement:     10,
				sizeofNeighElement:   10,
				sizeofSockRevElement: 10,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: 4294967,
				CTMapEntriesGlobalAny: 2147483,
				NATMapEntriesGlobal:   LimitTableMax + 1,
				NeighMapEntriesGlobal: LimitTableMax + 1, // default to same size as NAT
				WantErr:               true,
			},
		},
		{
			name: "Auth map size below range",
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFAuthMapMax: authMapEntriesMin - 1,
				},
				sizeofCTElement:      10,
				sizeofNATElement:     10,
				sizeofNeighElement:   10,
				sizeofSockRevElement: 10,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: 4294967,
				CTMapEntriesGlobalAny: 2147483,
				NATMapEntriesGlobal:   4294967,
				NeighMapEntriesGlobal: 4294967,
				AuthMapEntries:        authMapEntriesMin - 1,
				WantErr:               true,
			},
		},
		{
			name: "Auth map size above range",
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFAuthMapMax: authMapEntriesMax + 1,
				},
				sizeofCTElement:      10,
				sizeofNATElement:     10,
				sizeofNeighElement:   10,
				sizeofSockRevElement: 10,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: 4294967,
				CTMapEntriesGlobalAny: 2147483,
				NATMapEntriesGlobal:   4294967,
				NeighMapEntriesGlobal: 4294967,
				AuthMapEntries:        authMapEntriesMax + 1,
				WantErr:               true,
			},
		},
		{
			name: "Fragments map size below range",
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFAuthMapMax:      256,
					BPFFragmentsMapMax: fragmentsMapMin - 1,
				},
				sizeofCTElement:      10,
				sizeofNATElement:     10,
				sizeofNeighElement:   10,
				sizeofSockRevElement: 10,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: 4294967,
				CTMapEntriesGlobalAny: 2147483,
				NATMapEntriesGlobal:   4294967,
				NeighMapEntriesGlobal: 4294967,
				AuthMapEntries:        256,
				FragmentsMapEntries:   fragmentsMapMin - 1,
				WantErr:               true,
			},
		},
		{
			name: "Fragments map size above range",
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFAuthMapMax:      256,
					BPFFragmentsMapMax: fragmentsMapMax + 1,
				},
				sizeofCTElement:      10,
				sizeofNATElement:     10,
				sizeofNeighElement:   10,
				sizeofSockRevElement: 10,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: 4294967,
				CTMapEntriesGlobalAny: 2147483,
				NATMapEntriesGlobal:   4294967,
				NeighMapEntriesGlobal: 4294967,
				AuthMapEntries:        256,
				FragmentsMapEntries:   fragmentsMapMax + 1,
				WantErr:               true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// calculate with fixed memory and dynamic size ratio
			tt.c.calculateDynamicBPFMapSizes(64*GiB, 0.0025)

			err := tt.c.checkMapSizeLimits()

			got := sizes{
				AuthMapEntries:        tt.c.GetBPFAuthMapMax(),
				CTMapEntriesGlobalTCP: tt.c.GetBPFCTGlobalTCPMax(),
				CTMapEntriesGlobalAny: tt.c.GetBPFCTGlobalAnyMax(),
				NATMapEntriesGlobal:   tt.c.GetBPFNATGlobalMax(),
				FragmentsMapEntries:   tt.c.GetBPFFragmentsMapMax(),
				NeighMapEntriesGlobal: tt.c.GetBPFNeighGlobalMax(),
				WantErr:               err != nil,
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("BPFMapsSizeConfig.checkMapSizeLimits mismatch for '%s' (-want +got):\n%s", tt.name, diff)

				if err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestBPFMapSizeCalculation(t *testing.T) {
	cpus, _ := ebpf.PossibleCPU()

	type sizes struct {
		CTMapSizeTCP int
		CTMapSizeAny int
		NATMapSize   int
		NeighMapSize int
	}
	tests := []struct {
		name        string
		totalMemory uint64
		c           *bpfMapsSizeConfig
		want        sizes
	}{
		{
			name: "static default sizes",
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:      false,
					BPFMapDynamicSizeRatio: 0.0025,
					BPFNATGlobalMax:        0,
					BPFNeighGlobalMax:      0,
					BPFCTGlobalTCPMax:      0,
					BPFCTGlobalAnyMax:      0,
					BPFAuthMapMax:          1 << 19,
					BPFFragmentsMapMax:     8192,
				},
				sizeofCTElement:      94,
				sizeofNATElement:     94,
				sizeofNeighElement:   24,
				sizeofSockRevElement: 48,
			},
			want: sizes{
				CTMapSizeTCP: limitTableAutoGlobalTCPMin,
				CTMapSizeAny: limitTableAutoGlobalAnyMin,
				NATMapSize:   limitTableAutoNatGlobalMin,
				NeighMapSize: limitTableAutoNatGlobalMin,
			},
		},
		{
			name:        "dynamic size without any static sizes (512MB, 0.25%)",
			totalMemory: 512 * MiB,
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:      false,
					BPFMapDynamicSizeRatio: 0.0025,
					BPFNATGlobalMax:        0,
					BPFNeighGlobalMax:      0,
					BPFCTGlobalTCPMax:      0,
					BPFCTGlobalAnyMax:      0,
					BPFAuthMapMax:          1 << 19,
					BPFFragmentsMapMax:     8192,
				},
				sizeofCTElement:      94,
				sizeofNATElement:     94,
				sizeofNeighElement:   24,
				sizeofSockRevElement: 48,
			},
			want: sizes{
				CTMapSizeTCP: limitTableAutoGlobalTCPMin,
				CTMapSizeAny: limitTableAutoGlobalAnyMin,
				NATMapSize:   limitTableAutoNatGlobalMin,
				NeighMapSize: limitTableAutoNatGlobalMin,
			},
		},
		{
			name:        "dynamic size without any static sizes (1GiB, 0.25%)",
			totalMemory: 1 * GiB,
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:      false,
					BPFMapDynamicSizeRatio: 0.0025,
					BPFNATGlobalMax:        0,
					BPFNeighGlobalMax:      0,
					BPFCTGlobalTCPMax:      0,
					BPFCTGlobalAnyMax:      0,
					BPFAuthMapMax:          1 << 19,
					BPFFragmentsMapMax:     8192,
				},
				sizeofCTElement:      94,
				sizeofNATElement:     94,
				sizeofNeighElement:   24,
				sizeofSockRevElement: 48,
			},
			want: sizes{
				CTMapSizeTCP: limitTableAutoGlobalTCPMin,
				CTMapSizeAny: limitTableAutoGlobalAnyMin,
				NATMapSize:   limitTableAutoNatGlobalMin,
				NeighMapSize: limitTableAutoNatGlobalMin,
			},
		},
		{
			name:        "dynamic size without any static sizes (2GiB, 0.25%)",
			totalMemory: 2 * GiB,
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:      false,
					BPFMapDynamicSizeRatio: 0.0025,
					BPFNATGlobalMax:        0,
					BPFNeighGlobalMax:      0,
					BPFCTGlobalTCPMax:      0,
					BPFCTGlobalAnyMax:      0,
					BPFAuthMapMax:          1 << 19,
					BPFFragmentsMapMax:     8192,
				},
				sizeofCTElement:      94,
				sizeofNATElement:     94,
				sizeofNeighElement:   24,
				sizeofSockRevElement: 48,
			},
			want: sizes{
				CTMapSizeTCP: limitTableAutoGlobalTCPMin,
				CTMapSizeAny: limitTableAutoGlobalAnyMin,
				NATMapSize:   limitTableAutoNatGlobalMin,
				NeighMapSize: limitTableAutoNatGlobalMin,
			},
		},
		{
			name:        "dynamic size without any static sizes (7.5GiB, 0.25%)",
			totalMemory: 7.5 * GiB,
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:      false,
					BPFMapDynamicSizeRatio: 0.0025,
					BPFNATGlobalMax:        0,
					BPFNeighGlobalMax:      0,
					BPFCTGlobalTCPMax:      0,
					BPFCTGlobalAnyMax:      0,
					BPFAuthMapMax:          1 << 19,
					BPFFragmentsMapMax:     8192,
				},
				sizeofCTElement:      94,
				sizeofNATElement:     94,
				sizeofNeighElement:   24,
				sizeofSockRevElement: 48,
			},
			want: sizes{
				CTMapSizeTCP: limitTableAutoGlobalTCPMin,
				CTMapSizeAny: limitTableAutoGlobalAnyMin,
				NATMapSize:   limitTableAutoNatGlobalMin,
				NeighMapSize: limitTableAutoNatGlobalMin,
			},
		},
		{
			name:        "dynamic size without any static sizes (16GiB, 0.25%)",
			totalMemory: 16 * GiB,
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:      false,
					BPFMapDynamicSizeRatio: 0.0025,
					BPFNATGlobalMax:        0,
					BPFNeighGlobalMax:      0,
					BPFCTGlobalTCPMax:      0,
					BPFCTGlobalAnyMax:      0,
					BPFAuthMapMax:          1 << 19,
					BPFFragmentsMapMax:     8192,
				},
				sizeofCTElement:      94,
				sizeofNATElement:     94,
				sizeofNeighElement:   24,
				sizeofSockRevElement: 48,
			},
			want: sizes{
				CTMapSizeTCP: 151765,
				CTMapSizeAny: 75882,
				NATMapSize:   151765,
				NeighMapSize: 151765,
			},
		},
		{
			name:        "dynamic size without any static sizes (120GiB, 0.25%)",
			totalMemory: 30 * GiB,
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:      false,
					BPFMapDynamicSizeRatio: 0.0025,
					BPFNATGlobalMax:        0,
					BPFNeighGlobalMax:      0,
					BPFCTGlobalTCPMax:      0,
					BPFCTGlobalAnyMax:      0,
					BPFAuthMapMax:          1 << 19,
					BPFFragmentsMapMax:     8192,
				},
				sizeofCTElement:      94,
				sizeofNATElement:     94,
				sizeofNeighElement:   24,
				sizeofSockRevElement: 48,
			},
			want: sizes{
				CTMapSizeTCP: 284560,
				CTMapSizeAny: 142280,
				NATMapSize:   284560,
				NeighMapSize: 284560,
			},
		},
		{
			name:        "dynamic size without any static sizes (240GiB, 0.25%)",
			totalMemory: 240 * GiB,
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:      false,
					BPFMapDynamicSizeRatio: 0.0025,
					BPFNATGlobalMax:        0,
					BPFNeighGlobalMax:      0,
					BPFCTGlobalTCPMax:      0,
					BPFCTGlobalAnyMax:      0,
					BPFAuthMapMax:          1 << 19,
					BPFFragmentsMapMax:     8192,
				},
				sizeofCTElement:      94,
				sizeofNATElement:     94,
				sizeofNeighElement:   24,
				sizeofSockRevElement: 48,
			},
			want: sizes{
				CTMapSizeTCP: 2276484,
				CTMapSizeAny: 1138242,
				NATMapSize:   2276484,
				NeighMapSize: 2276484,
			},
		},
		{
			name:        "dynamic size without any static sizes (360GiB, 0.25%)",
			totalMemory: 360 * GiB,
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:      false,
					BPFMapDynamicSizeRatio: 0.0025,
					BPFNATGlobalMax:        0,
					BPFNeighGlobalMax:      0,
					BPFCTGlobalTCPMax:      0,
					BPFCTGlobalAnyMax:      0,
					BPFAuthMapMax:          1 << 19,
					BPFFragmentsMapMax:     8192,
				},
				sizeofCTElement:      94,
				sizeofNATElement:     94,
				sizeofNeighElement:   24,
				sizeofSockRevElement: 48,
			},
			want: sizes{
				CTMapSizeTCP: 3414726,
				CTMapSizeAny: 1707363,
				NATMapSize:   3414726,
				NeighMapSize: 3414726,
			},
		},
		{
			name:        "dynamic size with static CT TCP size (4GiB, 0.25%)",
			totalMemory: 4 * GiB,
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:      false,
					BPFMapDynamicSizeRatio: 0.0025,
					BPFNATGlobalMax:        0,
					BPFNeighGlobalMax:      0,
					BPFCTGlobalTCPMax:      ctMapEntriesGlobalTCPDefault + 1024,
					BPFCTGlobalAnyMax:      0,
					BPFAuthMapMax:          1 << 19,
					BPFFragmentsMapMax:     8192,
				},
				sizeofCTElement:      94,
				sizeofNATElement:     94,
				sizeofNeighElement:   24,
				sizeofSockRevElement: 48,
			},
			want: sizes{
				CTMapSizeTCP: ctMapEntriesGlobalTCPDefault + 1024,
				CTMapSizeAny: 65536,
				NATMapSize:   131072,
				NeighMapSize: 131072,
			},
		},
		{
			name:        "huge dynamic size ratio gets clamped (8GiB, 98%)",
			totalMemory: 16 * GiB,
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:      false,
					BPFMapDynamicSizeRatio: 0.98,
					BPFNATGlobalMax:        0,
					BPFNeighGlobalMax:      0,
					BPFCTGlobalTCPMax:      0,
					BPFCTGlobalAnyMax:      0,
					BPFAuthMapMax:          1 << 19,
					BPFFragmentsMapMax:     8192,
				},
				sizeofCTElement:      94,
				sizeofNATElement:     94,
				sizeofNeighElement:   24,
				sizeofSockRevElement: 48,
			},
			want: sizes{
				CTMapSizeTCP: LimitTableMax,
				CTMapSizeAny: LimitTableMax,
				NATMapSize:   LimitTableMax,
				NeighMapSize: LimitTableMax,
			},
		},
		{
			name:        "dynamic size NAT size above limit with static CT sizes (issue #13843)",
			totalMemory: 128 * GiB,
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:      false,
					BPFMapDynamicSizeRatio: 0.0025,
					BPFNATGlobalMax:        0,
					BPFNeighGlobalMax:      0,
					BPFCTGlobalTCPMax:      524288,
					BPFCTGlobalAnyMax:      262144,
					BPFAuthMapMax:          1 << 19,
					BPFFragmentsMapMax:     8192,
				},
				sizeofCTElement:      94,
				sizeofNATElement:     94,
				sizeofNeighElement:   24,
				sizeofSockRevElement: 48,
			},
			want: sizes{
				CTMapSizeTCP: 524288,
				CTMapSizeAny: 262144,
				NATMapSize:   (524288 + 262144) * 2 / 3,
				NeighMapSize: 524288,
			},
		},
		{
			name:        "dynamic size NAT size with distributed LRU",
			totalMemory: 3 * GiB,
			c: &bpfMapsSizeConfig{
				logger: hivetest.Logger(t),
				flags: BPFMapsSizeFlags{
					BPFDistributedLRU:      true,
					BPFMapDynamicSizeRatio: 0.051,
					BPFNATGlobalMax:        0,
					BPFNeighGlobalMax:      0,
					BPFCTGlobalTCPMax:      0,
					BPFCTGlobalAnyMax:      0,
					BPFAuthMapMax:          1 << 19,
					BPFFragmentsMapMax:     8192,
				},
				sizeofCTElement:      94,
				sizeofNATElement:     94,
				sizeofNeighElement:   24,
				sizeofSockRevElement: 48,
			},
			want: sizes{
				CTMapSizeTCP: util.RoundUp(580503, cpus),
				CTMapSizeAny: util.RoundUp(290251, cpus),
				NATMapSize:   util.RoundUp(580503, cpus),
				NeighMapSize: util.RoundUp(580503, cpus),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.c.calculateDynamicBPFMapSizes(tt.totalMemory, tt.c.GetBPFMapDynamicSizeRatio())

			got := sizes{
				tt.c.GetBPFCTGlobalTCPMax(),
				tt.c.GetBPFCTGlobalAnyMax(),
				tt.c.GetBPFNATGlobalMax(),
				tt.c.GetBPFNeighGlobalMax(),
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("DaemonConfig.calculateDynamicBPFMapSize (-want +got):\n%s", diff)
			}
		})
	}
}
