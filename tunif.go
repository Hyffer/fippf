package main

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
	"net"
)

type TunIf struct {
	tun.Device
	name  string
	mtu   int
	ip    net.IP
	cidr  net.IPNet
	ip6   net.IP
	cidr6 net.IPNet
}

func (tunIf *TunIf) Close() {
	if tunIf != nil && tunIf.Device != nil {
		_ = tunIf.Device.Close()
	}
}

func NewTunIf(ifName string, mtu int, ipRange string, ip6Range string) (*TunIf, error) {
	ip, cidr, err := net.ParseCIDR(ipRange) // is address valid to assign to interface?
	if err != nil {
		return nil, fmt.Errorf("cannot parse IPv4 range: %w", err)
	}
	ip6, cidr6, err := net.ParseCIDR(ip6Range)
	if err != nil {
		return nil, fmt.Errorf("cannot parse IPv6 range: %w", err)
	}

	device, err := tun.CreateTUN(ifName, mtu)
	if err != nil {
		return nil, fmt.Errorf("cannot create TUN device: %w", err)
	}
	tunIf := TunIf{
		Device: device,
		mtu:    mtu,
		name:   ifName,
		ip:     ip,
		cidr:   *cidr,
		ip6:    ip6,
		cidr6:  *cidr6,
	}

	err = setupTunIf(ifName, ip, cidr, ip6, cidr6)
	if err != nil {
		tunIf.Close()
		return nil, fmt.Errorf("failed to setup TUN device: %w", err)
	}

	return &tunIf, nil
}

func setupTunIf(ifName string, ip net.IP, cidr *net.IPNet, ip6 net.IP, cidr6 *net.IPNet) error {
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
