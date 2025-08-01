// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package sock

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"go4.org/netipx"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/common"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

// Parser is a parser for SockTraceNotify payloads
type Parser struct {
	log            *slog.Logger
	endpointGetter getters.EndpointGetter
	identityGetter getters.IdentityGetter
	dnsGetter      getters.DNSGetter
	ipGetter       getters.IPGetter
	serviceGetter  getters.ServiceGetter
	cgroupGetter   getters.PodMetadataGetter
	epResolver     *common.EndpointResolver

	skipUnknownCGroupIDs bool
}

// New creates a new parser
func New(log *slog.Logger,
	endpointGetter getters.EndpointGetter,
	identityGetter getters.IdentityGetter,
	dnsGetter getters.DNSGetter,
	ipGetter getters.IPGetter,
	serviceGetter getters.ServiceGetter,
	cgroupGetter getters.PodMetadataGetter,
	opts ...options.Option,
) (*Parser, error) {
	args := &options.Options{
		SkipUnknownCGroupIDs: true,
	}

	for _, opt := range opts {
		opt(args)
	}

	return &Parser{
		log:                  log,
		endpointGetter:       endpointGetter,
		identityGetter:       identityGetter,
		dnsGetter:            dnsGetter,
		ipGetter:             ipGetter,
		serviceGetter:        serviceGetter,
		cgroupGetter:         cgroupGetter,
		epResolver:           common.NewEndpointResolver(log, endpointGetter, identityGetter, ipGetter),
		skipUnknownCGroupIDs: args.SkipUnknownCGroupIDs,
	}, nil
}

// Decode takes a raw trace sock event payload obtained from the perf event ring
// buffer and decodes it into a flow
func (p *Parser) Decode(data []byte, decoded *flowpb.Flow) error {
	if len(data) == 0 {
		return errors.ErrEmptyData
	}

	eventType := data[0]
	if eventType != monitorAPI.MessageTypeTraceSock {
		return errors.NewErrInvalidType(eventType)
	}

	sock := &monitor.TraceSockNotify{}
	if err := sock.Decode(data); err != nil {
		return fmt.Errorf("failed to parse sock trace event: %w", err)
	}

	ipVersion := decodeIPVersion(sock.Flags)
	srcIP := p.decodeEndpointIP(sock.CgroupId, ipVersion)
	if !srcIP.IsValid() && p.skipUnknownCGroupIDs {
		// Skip events for which we cannot determine the endpoint ip based on
		// the numeric cgroup id, since those events do not provide much value
		// to end users.
		return errors.ErrEventSkipped
	}
	srcPort := uint16(0) // source port is not known for TraceSock events

	// Ignore invalid IPs - getters will handle invalid values.
	// IPs can be empty for Ethernet-only packets.
	dstIP, _ := netipx.FromStdIP(sock.IP())
	dstPort := sock.DstPort

	datapathContext := common.DatapathContext{
		SrcIP:      srcIP,
		SrcLabelID: 0,
		DstIP:      dstIP,
		DstLabelID: 0,
	}
	srcEndpoint := p.epResolver.ResolveEndpoint(srcIP, 0, datapathContext)
	dstEndpoint := p.epResolver.ResolveEndpoint(dstIP, 0, datapathContext)

	// On the reverse path, source and destination IP of the packet are reversed
	isRevNat := decodeRevNat(sock.XlatePoint)
	if isRevNat {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
		srcEndpoint, dstEndpoint = dstEndpoint, srcEndpoint
	}

	decoded.Verdict = decodeVerdict(sock.XlatePoint)
	decoded.IP = decodeL3(srcIP, dstIP, ipVersion)
	decoded.L4 = decodeL4(sock.L4Proto, srcPort, dstPort)
	decoded.Source = srcEndpoint
	decoded.SourceNames = p.resolveNames(dstEndpoint.GetID(), srcIP)
	decoded.SourceService = p.decodeService(srcIP, srcPort)
	decoded.Destination = dstEndpoint
	decoded.DestinationService = p.decodeService(dstIP, dstPort)
	decoded.DestinationNames = p.resolveNames(srcEndpoint.GetID(), dstIP)
	decoded.Type = flowpb.FlowType_SOCK
	decoded.EventType = decodeCiliumEventType(sock.Type, sock.XlatePoint)
	decoded.SockXlatePoint = flowpb.SocketTranslationPoint(sock.XlatePoint)
	decoded.SocketCookie = sock.SockCookie
	decoded.CgroupId = sock.CgroupId
	decoded.Summary = decodeSummary(sock)
	return nil
}

func decodeIPVersion(flags uint8) flowpb.IPVersion {
	if (flags & monitor.TraceSockNotifyFlagIPv6) != 0 {
		return flowpb.IPVersion_IPv6
	}
	return flowpb.IPVersion_IPv4
}

func (p *Parser) decodeEndpointIP(cgroupId uint64, ipVersion flowpb.IPVersion) netip.Addr {
	if p.cgroupGetter != nil {
		if m := p.cgroupGetter.GetPodMetadataForContainer(cgroupId); m != nil {
			for _, podIP := range m.IPs {
				isIPv6 := strings.Contains(podIP, ":")
				if isIPv6 && ipVersion == flowpb.IPVersion_IPv6 ||
					!isIPv6 && ipVersion == flowpb.IPVersion_IPv4 {
					ip, err := netip.ParseAddr(podIP)
					if err != nil {
						p.log.Debug(
							"failed to parse pod IP",
							logfields.Error, err,
							logfields.CGroupID, cgroupId,
							logfields.K8sPodName, m.Name,
							logfields.K8sNamespace, m.Namespace,
							logfields.IPAddr, podIP,
						)
						return netip.Addr{}
					}
					return ip
				}
			}
			p.log.Debug(
				"no matching IP for pod",
				logfields.CGroupID, cgroupId,
				logfields.K8sPodName, m.Name,
				logfields.K8sNamespace, m.Namespace,
			)
		}
	}
	return netip.Addr{}
}

func decodeL3(srcIP, dstIP netip.Addr, ipVersion flowpb.IPVersion) *flowpb.IP {
	var srcIPStr, dstIPStr string
	if srcIP.IsValid() {
		srcIPStr = srcIP.String()
	}
	if dstIP.IsValid() {
		dstIPStr = dstIP.String()
	}

	return &flowpb.IP{
		Source:      srcIPStr,
		Destination: dstIPStr,
		IpVersion:   ipVersion,
	}
}

func decodeL4(proto uint8, srcPort, dstPort uint16) *flowpb.Layer4 {
	switch proto {
	case monitor.L4ProtocolTCP:
		return &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					SourcePort:      uint32(srcPort),
					DestinationPort: uint32(dstPort),
				},
			},
		}
	case monitor.L4ProtocolUDP:
		return &flowpb.Layer4{
			Protocol: &flowpb.Layer4_UDP{
				UDP: &flowpb.UDP{
					SourcePort:      uint32(srcPort),
					DestinationPort: uint32(dstPort),
				},
			},
		}
	}

	return nil
}

func (p *Parser) resolveNames(epID uint32, ip netip.Addr) (names []string) {
	if p.dnsGetter != nil {
		return p.dnsGetter.GetNamesOf(epID, ip)
	}

	return nil
}

func (p *Parser) decodeService(ip netip.Addr, port uint16) *flowpb.Service {
	if p.serviceGetter != nil {
		return p.serviceGetter.GetServiceByAddr(ip, port)
	}

	return nil
}

func decodeVerdict(xlatePoint uint8) flowpb.Verdict {
	switch xlatePoint {
	case monitor.XlatePointPreDirectionFwd,
		monitor.XlatePointPreDirectionRev:
		return flowpb.Verdict_TRACED
	case monitor.XlatePointPostDirectionFwd,
		monitor.XlatePointPostDirectionRev:
		return flowpb.Verdict_TRANSLATED
	}

	return flowpb.Verdict_VERDICT_UNKNOWN
}

func decodeRevNat(xlatePoint uint8) bool {
	switch xlatePoint {
	case monitor.XlatePointPreDirectionRev,
		monitor.XlatePointPostDirectionRev:
		return true
	}

	return false
}

func decodeCiliumEventType(eventType, subtype uint8) *flowpb.CiliumEventType {
	return &flowpb.CiliumEventType{
		Type:    int32(eventType),
		SubType: int32(subtype),
	}
}

func decodeSummary(sock *monitor.TraceSockNotify) string {
	switch sock.L4Proto {
	case monitor.L4ProtocolTCP:
		return "TCP"
	case monitor.L4ProtocolUDP:
		return "UDP"
	default:
		return "Unknown"
	}
}
