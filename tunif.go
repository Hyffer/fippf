package main

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"log/slog"
	"net"
)

const (
	tcpProtocolNumber = 6
	udpProtocolNumber = 17
)

type TunIf struct {
	exits []func()
	stack *stack.Stack
	name  string
	mtu   uint32
	ip    net.IP
	cidr  net.IPNet
	ip6   net.IP
	cidr6 net.IPNet
}

func (tunIf *TunIf) atexit(exit func()) {
	tunIf.exits = append([]func(){exit}, tunIf.exits...)
}

func (tunIf *TunIf) Close() {
	for _, exit := range tunIf.exits {
		exit()
	}
}

func NewTunIf(ifName string, mtu uint32, ipRange string, ip6Range string) (*TunIf, error) {
	ip, cidr, err := net.ParseCIDR(ipRange) // is address valid to assign to interface?
	if err != nil {
		return nil, fmt.Errorf("cannot parse IPv4 range: %w", err)
	}
	ip6, cidr6, err := net.ParseCIDR(ip6Range)
	if err != nil {
		return nil, fmt.Errorf("cannot parse IPv6 range: %w", err)
	}

	// create virtual network stack
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal: false,
	})

	tunIf := TunIf{
		exits: []func(){func() {
			s.Close()
		}},
		stack: s,
		name:  ifName,
		mtu:   mtu,
		ip:    ip,
		cidr:  *cidr,
		ip6:   ip6,
		cidr6: *cidr6,
	}

	// create TUN device
	fd, err := tun.Open(ifName)
	if err != nil {
		tunIf.Close()
		return nil, fmt.Errorf("cannot create TUN device: %w", err)
	}
	tunIf.atexit(func() {
		_ = unix.Close(fd)
	})

	// bind TUN device to virtual network stack
	linkEP, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: mtu})
	if err != nil {
		tunIf.Close()
		return nil, fmt.Errorf("failed to create link endpoint: %w", err)
	}
	ipErr := s.CreateNIC(1, linkEP)
	if ipErr != nil {
		tunIf.Close()
		return nil, fmt.Errorf("failed to create NIC in virtual network stack: %s", ipErr.String())
	}
	tunIf.atexit(func() {
		_ = s.RemoveNIC(1)
	})

	// configure TunIf
	err = tunIf.setupTunIf(ip, cidr, ip6, cidr6)
	if err != nil {
		tunIf.Close()
		return nil, fmt.Errorf("failed to setup TUN device: %w", err)
	}

	return &tunIf, nil
}

func (tunIf *TunIf) setupTunIf(ip net.IP, cidr *net.IPNet, ip6 net.IP, cidr6 *net.IPNet) error {
	// configure virtual network stack
	// are these configs necessary and correct?
	s := tunIf.stack
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         1,
	}, {
		Destination: header.IPv6EmptySubnet,
		NIC:         1,
	}})

	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)

	// configure TUN device
	ifName := tunIf.name
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("device \"%s\" not found: %w", ifName, err)
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("cannot bring up TUN device: %w", err)
	}

	addr4 := netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: cidr.Mask}}
	addr6 := netlink.Addr{IPNet: &net.IPNet{IP: ip6, Mask: cidr6.Mask}}
	for _, addr := range []netlink.Addr{addr4, addr6} {
		err = netlink.AddrAdd(link, &addr)
		if err != nil {
			return fmt.Errorf("cannot add address %s to TUN device: %w", addr, err)
		}
	}

	// there is no need to manually set routes for TUN device,
	// because its address is inside the ip range

	return nil
}

func (tunIf *TunIf) SetConnHandler(handler func(t uint32, conn net.Conn)) {
	tcpHandler := tcp.NewForwarder(tunIf.stack, 0, 4096, func(request *tcp.ForwarderRequest) {
		var wq waiter.Queue
		ep, ipErr := request.CreateEndpoint(&wq)
		if ipErr != nil {
			slog.Error("Error creating endpoint for TCP forwarder:", "err", ipErr, "request", request)
		}
		tcpConn := gonet.NewTCPConn(&wq, ep)

		handler(tcpProtocolNumber, tcpConn)
	})
	tunIf.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandler.HandlePacket)
}
