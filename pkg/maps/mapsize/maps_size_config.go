package mapsize

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/mackerelio/go-osstat/memory"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/util"
)

const (
	BPFDistributedLRUFlagName = "bpf-distributed-lru"

	ctMapEntriesGlobalTCPName = "bpf-ct-global-tcp-max"
	ctMapEntriesGlobalAnyName = "bpf-ct-global-any-max"
	natMapEntriesGlobalName   = "bpf-nat-global-max"
	neighMapEntriesGlobalName = "bpf-neigh-global-max"
)

const (
	ctMapEntriesGlobalTCPDefault = 2 << 18 // 512Ki
	ctMapEntriesGlobalAnyDefault = 2 << 17 // 256Ki

	// natMapEntriesGlobalDefault holds the default size of the NAT map
	// and is 2/3 of the full CT size as a heuristic
	natMapEntriesGlobalDefault = int((ctMapEntriesGlobalTCPDefault + ctMapEntriesGlobalAnyDefault) * 2 / 3)

	// SockRevNATMapEntriesDefault holds the default size of the SockRev NAT map
	// and is the same size of CTMapEntriesGlobalAnyDefault as a heuristic given
	// that sock rev NAT is mostly used for UDP and getpeername only.
	SockRevNATMapEntriesDefault = ctMapEntriesGlobalAnyDefault
)

const (
	limitTableAutoGlobalTCPMin  = 1 << 17 // 128Ki entries
	limitTableAutoGlobalAnyMin  = 1 << 16 // 64Ki entries
	limitTableAutoNatGlobalMin  = 1 << 17 // 128Ki entries
	LimitTableAutoSockRevNatMin = 1 << 16 // 64Ki entries
)

const (
	LimitTableMin = 1 << 10 // 1Ki entries
	LimitTableMax = 1 << 24 // 16Mi entries (~1GiB of entries per map)

	authMapEntriesMin = 1 << 8
	authMapEntriesMax = 1 << 24

	fragmentsMapMin = 1 << 8
	fragmentsMapMax = 1 << 16
)

// ConfigCell provides the BPF map size flag config.
var ConfigCell = cell.Config(BPFMapsSizeFlags{
	BPFDistributedLRU:      false,
	BPFMapDynamicSizeRatio: 0.0025,

	BPFAuthMapMax:      1 << 19,
	BPFFragmentsMapMax: 8192,

	// Default to 0 -> dynamic size calculation
	// This is necessary to detect whether a value has been set by the user or not.
	BPFNATGlobalMax:   0,
	BPFNeighGlobalMax: 0,
	BPFCTGlobalTCPMax: 0,
	BPFCTGlobalAnyMax: 0,
})

type BPFMapsSizeFlags struct {
	BPFDistributedLRU      bool
	BPFMapDynamicSizeRatio float64

	BPFNATGlobalMax   int
	BPFNeighGlobalMax int
	BPFCTGlobalTCPMax int
	BPFCTGlobalAnyMax int

	BPFAuthMapMax      int
	BPFFragmentsMapMax int
}

func (r BPFMapsSizeFlags) Flags(flags *pflag.FlagSet) {
	flags.Bool(BPFDistributedLRUFlagName, r.BPFDistributedLRU, "Enable per-CPU BPF LRU backend memory")
	flags.Float64("bpf-map-dynamic-size-ratio", r.BPFMapDynamicSizeRatio, "Ratio (0.0-1.0] of total system memory to use for dynamic sizing of CT, NAT and policy BPF maps")

	flags.Int("bpf-ct-global-tcp-max", r.BPFCTGlobalTCPMax, fmt.Sprintf("Maximum number of entries in TCP CT table (auto-calculated by default - otherwise %d)", ctMapEntriesGlobalTCPDefault))
	flags.Int("bpf-ct-global-any-max", r.BPFCTGlobalAnyMax, fmt.Sprintf("Maximum number of entries in non-TCP CT table (auto-calculated by default - otherwise %d)", ctMapEntriesGlobalAnyDefault))
	flags.Int("bpf-nat-global-max", r.BPFNATGlobalMax, fmt.Sprintf("Maximum number of entries for the global BPF NAT table (auto-calculated by default - otherwise %d)", natMapEntriesGlobalDefault))
	flags.Int("bpf-neigh-global-max", r.BPFNeighGlobalMax, fmt.Sprintf("Maximum number of entries for the global BPF neighbor table (auto-calculated by default - otherwise %d", natMapEntriesGlobalDefault))

	flags.Int("bpf-auth-map-max", r.BPFAuthMapMax, "Maximum number of entries in auth map")
	flags.Int("bpf-fragments-map-max", r.BPFFragmentsMapMax, "Maximum number of entries in fragments tracking map")
}

// BPFMapsSizeConfig can be usesd to retrieve BPF map size configs.
// This includes the ones that have been dynamically evaluated
// (CT, NAT, neighbors, ...).
type BPFMapsSizeConfig interface {
	GetDynamicSize(def int, min int, max int) (int, error)

	GetBPFDistributedLRU() bool
	GetBPFMapDynamicSizeRatio() float64

	GetBPFCTGlobalTCPMax() int
	GetBPFCTGlobalAnyMax() int
	GetBPFNATGlobalMax() int
	GetBPFNeighGlobalMax() int

	GetBPFAuthMapMax() int
	GetBPFFragmentsMapMax() int
}

type bpfMapsSizeConfig struct {
	logger *slog.Logger

	flags BPFMapsSizeFlags

	sizeofCTElement      int
	sizeofNATElement     int
	sizeofNeighElement   int
	sizeofSockRevElement int

	// These are the values that have been either copied from the
	// flags or evaluated based on the dynamic size ratio.
	actualBPFNATGlobalMax   int
	actualBPFNeighGlobalMax int
	actualBPFCTGlobalTCPMax int
	actualBPFCTGlobalAnyMax int
}

func NewBPFMapsSizeConfig(logger *slog.Logger, flags BPFMapsSizeFlags, ct int, nat int, neigh int, sockrev int) (BPFMapsSizeConfig, error) {
	provider := &bpfMapsSizeConfig{
		logger: logger,
		flags:  flags,

		sizeofCTElement:      ct,
		sizeofNATElement:     nat,
		sizeofNeighElement:   neigh,
		sizeofSockRevElement: sockrev,
	}

	if err := provider.calculateBPFMapSizes(); err != nil {
		return nil, fmt.Errorf("failed to calculate BPF map sizes: %w", err)
	}

	if err := provider.checkMapSizeLimits(); err != nil {
		return nil, fmt.Errorf("failed to check map size limits: %w", err)
	}

	return provider, nil
}

func (r *bpfMapsSizeConfig) GetBPFDistributedLRU() bool {
	return r.flags.BPFDistributedLRU
}

func (r *bpfMapsSizeConfig) GetBPFMapDynamicSizeRatio() float64 {
	return r.flags.BPFMapDynamicSizeRatio
}

func (r *bpfMapsSizeConfig) GetBPFCTGlobalAnyMax() int {
	return r.actualBPFCTGlobalAnyMax
}

func (r *bpfMapsSizeConfig) GetBPFCTGlobalTCPMax() int {
	return r.actualBPFCTGlobalTCPMax
}

func (r *bpfMapsSizeConfig) GetBPFNATGlobalMax() int {
	return r.actualBPFNATGlobalMax
}

func (r *bpfMapsSizeConfig) GetBPFNeighGlobalMax() int {
	return r.actualBPFNeighGlobalMax
}

func (r *bpfMapsSizeConfig) GetBPFAuthMapMax() int {
	return r.flags.BPFAuthMapMax
}

func (r *bpfMapsSizeConfig) GetBPFFragmentsMapMax() int {
	return r.flags.BPFFragmentsMapMax
}

func (r *bpfMapsSizeConfig) calculateBPFMapSizes() error {
	// Allow the range (0.0, 1.0] because the dynamic size will anyway be
	// clamped to the table limits. Thus, a ratio of e.g. 0.98 will not lead
	// to 98% of the total memory being allocated for BPF maps.
	dynamicSizeRatio := r.flags.BPFMapDynamicSizeRatio

	if dynamicSizeRatio < 0.0 || dynamicSizeRatio > 1 {
		return fmt.Errorf("specified dynamic map size ratio %f must be > 0.0 and <= 1.0", dynamicSizeRatio)
	}

	totalMemory, err := r.getTotalMemory()
	if err != nil {
		return err
	}

	r.calculateDynamicBPFMapSizes(totalMemory, dynamicSizeRatio)

	return nil
}

func (r *bpfMapsSizeConfig) GetDynamicSize(def int, min int, max int) (int, error) {
	totalMemory, err := r.getTotalMemory()
	if err != nil {
		return 0, err
	}

	calculate := r.getDynamicSizeCalculator(r.flags.BPFMapDynamicSizeRatio, totalMemory)

	return calculate(def, min, max), nil
}

func (r *bpfMapsSizeConfig) getTotalMemory() (uint64, error) {
	vms, err := memory.Get()
	if err != nil || vms == nil {
		return 0, fmt.Errorf("failed to get system memory: %w", err)
	}

	return vms.Total, nil
}

func (r *bpfMapsSizeConfig) getDynamicSizeCalculator(dynamicSizeRatio float64, totalMemory uint64) func(def int, min int, max int) int {
	if 0.0 >= dynamicSizeRatio || dynamicSizeRatio > 1.0 {
		return func(def int, min int, max int) int { return def }
	}

	possibleCPUs := 1
	// Heuristic:
	// Distribute relative to map default entries among the different maps.
	// Cap each map size by the maximum. Map size provided by the user will
	// override the calculated value and also the max. There will be a check
	// for maximum size later on in DaemonConfig.Validate()
	//
	// Calculation examples:
	//
	// Memory   CT TCP  CT Any      NAT
	//
	//  512MB    33140   16570    33140
	//    1GB    66280   33140    66280
	//    4GB   265121  132560   265121
	//   16GB  1060485  530242  1060485

	memoryAvailableForMaps := int(float64(totalMemory) * dynamicSizeRatio)
	r.logger.Info(fmt.Sprintf("Memory available for map entries (%.3f%% of %dB): %dB", dynamicSizeRatio*100, totalMemory, memoryAvailableForMaps))

	totalMapMemoryDefault := ctMapEntriesGlobalTCPDefault*r.sizeofCTElement +
		ctMapEntriesGlobalAnyDefault*r.sizeofCTElement +
		natMapEntriesGlobalDefault*r.sizeofNATElement +
		natMapEntriesGlobalDefault*r.sizeofNeighElement +
		SockRevNATMapEntriesDefault*r.sizeofSockRevElement

	r.logger.Debug(fmt.Sprintf("Total memory for default map entries: %d", totalMapMemoryDefault))

	// In case of distributed LRU, we need to round up to the number of possible CPUs
	// since this is also what the kernel does internally, see htab_map_alloc()'s:
	//
	//   htab->map.max_entries = roundup(attr->max_entries,
	//				     num_possible_cpus());
	//
	// Thus, if we would not round up from agent side, then Cilium would constantly
	// try to replace maps due to property mismatch!
	if r.flags.BPFDistributedLRU {
		cpus, err := ebpf.PossibleCPU()
		if err != nil {
			logging.Fatal(r.logger, "Failed to get number of possible CPUs needed for the distributed LRU")
		}
		possibleCPUs = cpus
	}

	return func(entriesDefault, min, max int) int {
		entries := (entriesDefault * memoryAvailableForMaps) / totalMapMemoryDefault
		entries = util.RoundUp(entries, possibleCPUs)
		if entries < min {
			entries = util.RoundUp(min, possibleCPUs)
		} else if entries > max {
			entries = util.RoundDown(max, possibleCPUs)
		}
		return entries
	}
}

func (r *bpfMapsSizeConfig) calculateDynamicBPFMapSizes(totalMemory uint64, dynamicSizeRatio float64) {
	calculate := r.getDynamicSizeCalculator(dynamicSizeRatio, totalMemory)

	// If value for a particular map was explicitly set by an
	// option, disable dynamic sizing for this map and use the
	// provided size.
	if r.flags.BPFCTGlobalTCPMax == 0 {
		r.actualBPFCTGlobalTCPMax = calculate(ctMapEntriesGlobalTCPDefault, limitTableAutoGlobalTCPMin, LimitTableMax)
		r.logger.Info(fmt.Sprintf("option %s set by dynamic sizing to %v", ctMapEntriesGlobalTCPName, r.actualBPFCTGlobalTCPMax))
	} else {
		r.actualBPFCTGlobalTCPMax = r.flags.BPFCTGlobalTCPMax
		r.logger.Debug(fmt.Sprintf("option %s set by user to %v", ctMapEntriesGlobalTCPName, r.actualBPFCTGlobalTCPMax))
	}

	if r.flags.BPFCTGlobalAnyMax == 0 {
		r.actualBPFCTGlobalAnyMax = calculate(ctMapEntriesGlobalAnyDefault, limitTableAutoGlobalAnyMin, LimitTableMax)
		r.logger.Info(fmt.Sprintf("option %s set by dynamic sizing to %v", ctMapEntriesGlobalAnyName, r.actualBPFCTGlobalAnyMax))
	} else {
		r.actualBPFCTGlobalAnyMax = r.flags.BPFCTGlobalAnyMax
		r.logger.Debug(fmt.Sprintf("option %s set by user to %v", ctMapEntriesGlobalAnyName, r.actualBPFCTGlobalAnyMax))
	}

	if r.flags.BPFNATGlobalMax == 0 {
		r.actualBPFNATGlobalMax = calculate(natMapEntriesGlobalDefault, limitTableAutoNatGlobalMin, LimitTableMax)
		r.logger.Info(fmt.Sprintf("option %s set by dynamic sizing to %v", natMapEntriesGlobalName, r.actualBPFNATGlobalMax))
		if r.actualBPFNATGlobalMax > r.actualBPFCTGlobalTCPMax+r.actualBPFCTGlobalAnyMax {
			// CT table size was specified manually, make sure that the NAT table size
			// does not exceed maximum CT table size. See checkMapSizeLimits.
			r.actualBPFNATGlobalMax = (r.actualBPFCTGlobalTCPMax + r.actualBPFCTGlobalAnyMax) * 2 / 3
			r.logger.Warn(fmt.Sprintf("option %s would exceed maximum determined by CT table sizes, capping to %v", natMapEntriesGlobalName, r.actualBPFNATGlobalMax))
		}
	} else {
		r.actualBPFNATGlobalMax = r.flags.BPFNATGlobalMax
		r.logger.Debug(fmt.Sprintf("option %s set by user to %v", natMapEntriesGlobalName, r.actualBPFNATGlobalMax))
	}

	if r.flags.BPFNeighGlobalMax == 0 {
		// By default we auto-size it to the same value as the NAT map since we
		// need to keep at least as many neigh entries.
		r.actualBPFNeighGlobalMax = r.actualBPFNATGlobalMax
		r.logger.Info(fmt.Sprintf("option %s set by dynamic sizing to %v", neighMapEntriesGlobalName, r.actualBPFNeighGlobalMax))
	} else {
		r.actualBPFNeighGlobalMax = r.flags.BPFNeighGlobalMax
		r.logger.Debug(fmt.Sprintf("option %s set by user to %v", neighMapEntriesGlobalName, r.actualBPFNeighGlobalMax))
	}
}

func (r *bpfMapsSizeConfig) checkMapSizeLimits() error {
	if r.actualBPFCTGlobalTCPMax < LimitTableMin || r.actualBPFCTGlobalAnyMax < LimitTableMin {
		return fmt.Errorf("specified CT tables values %d/%d must be greater or equal to %d",
			r.actualBPFCTGlobalTCPMax, r.actualBPFCTGlobalAnyMax, LimitTableMin)
	}
	if r.actualBPFCTGlobalTCPMax > LimitTableMax || r.actualBPFCTGlobalAnyMax > LimitTableMax {
		return fmt.Errorf("specified CT tables values %d/%d must not exceed maximum %d",
			r.actualBPFCTGlobalTCPMax, r.actualBPFCTGlobalAnyMax, LimitTableMax)
	}

	if r.actualBPFNATGlobalMax < LimitTableMin {
		return fmt.Errorf("specified NAT table size %d must be greater or equal to %d",
			r.actualBPFNATGlobalMax, LimitTableMin)
	}
	if r.actualBPFNATGlobalMax > LimitTableMax {
		return fmt.Errorf("specified NAT tables size %d must not exceed maximum %d",
			r.actualBPFNATGlobalMax, LimitTableMax)
	}
	if r.actualBPFNATGlobalMax > r.actualBPFCTGlobalTCPMax+r.actualBPFCTGlobalAnyMax {
		if r.actualBPFNATGlobalMax == natMapEntriesGlobalDefault {
			// Auto-size for the case where CT table size was adapted but NAT still on default
			r.actualBPFNATGlobalMax = int((r.actualBPFCTGlobalTCPMax + r.actualBPFCTGlobalAnyMax) * 2 / 3)
		} else {
			return fmt.Errorf("specified NAT tables size %d must not exceed maximum CT table size %d",
				r.actualBPFNATGlobalMax, r.actualBPFCTGlobalTCPMax+r.actualBPFCTGlobalAnyMax)
		}
	}

	if r.flags.BPFAuthMapMax < authMapEntriesMin {
		return fmt.Errorf("specified AuthMap max entries %d must be greater or equal to %d", r.flags.BPFAuthMapMax, authMapEntriesMin)
	}
	if r.flags.BPFAuthMapMax > authMapEntriesMax {
		return fmt.Errorf("specified AuthMap max entries %d must not exceed maximum %d", r.flags.BPFAuthMapMax, authMapEntriesMax)
	}

	if r.flags.BPFFragmentsMapMax < fragmentsMapMin {
		return fmt.Errorf("specified max entries %d for fragment-tracking map must be greater or equal to %d",
			r.flags.BPFFragmentsMapMax, fragmentsMapMin)
	}
	if r.flags.BPFFragmentsMapMax > fragmentsMapMax {
		return fmt.Errorf("specified max entries %d for fragment-tracking map must not exceed maximum %d",
			r.flags.BPFFragmentsMapMax, fragmentsMapMax)
	}

	return nil
}
