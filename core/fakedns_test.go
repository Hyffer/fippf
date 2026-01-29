package core

import (
	"fmt"
	"github.com/deckarep/golang-set"
	"net"
	"testing"
)

func mustParseCIDR(t *testing.T, s string) (net.IPNet, net.IP) {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("failed to parse cidr %q: %v", s, err)
	}
	return *ipnet, ip
}

// populateIPPoolCap4 creates an IPPool with 4 available IP addresses (idx = 3, 4, 5, 6).
// This is a common setup method used across multiple tests.
func populateIPPoolCap4(t *testing.T) *IPPool {
	t.Helper()
	cidr, reserveIP := mustParseCIDR(t, "192.0.2.1/29")
	cidr6, reserveIP6 := mustParseCIDR(t, "2001:db8::2/120")
	pool := NewIPPool(cidr, reserveIP, cidr6, reserveIP6)
	if pool == nil {
		t.Fatalf("failed to create IPPool")
	}
	return pool
}

func TestIPPoolCreation(t *testing.T) {
	tests := []struct {
		ip              string
		ip6             string
		expectedSize    uint32
		expectedReserve mapset.Set
	}{
		{
			ip:              "192.0.2.1/24",
			ip6:             "2001:db8::1/120",
			expectedSize:    256,
			expectedReserve: mapset.NewSet(uint32(0), uint32(1), uint32(255)),
		},
		{
			ip:              "192.0.2.3/24",
			ip6:             "2001:db8::7/121",
			expectedSize:    128,
			expectedReserve: mapset.NewSet(uint32(0), uint32(3), uint32(7), uint32(127)),
		},
		// the following depend on current specific implementation
		{
			ip:              "192.0.2.1/30",
			ip6:             "2001:db8::1:0:2/64",
			expectedSize:    4,
			expectedReserve: mapset.NewSet(uint32(0), uint32(1), uint32(3)),
		},
		{
			ip:              "0.0.1.1/0",
			ip6:             "2001:db8::2/96",
			expectedSize:    0xffffffff,
			expectedReserve: mapset.NewSet(uint32(0), uint32(0x101), uint32(2), uint32(0xfffffffe)),
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("ip=%s,ip6=%s", tt.ip, tt.ip6), func(t *testing.T) {
			cidr, reserveIP := mustParseCIDR(t, tt.ip)
			cidr6, reserveIP6 := mustParseCIDR(t, tt.ip6)

			pool := NewIPPool(cidr, reserveIP, cidr6, reserveIP6)
			if pool == nil {
				t.Fatalf("Error creating IPPool")
			}
			if pool.size != tt.expectedSize {
				t.Fatalf("Unexpected pool.size: got %d want %d", pool.size, tt.expectedSize)
			}
			if !pool.reserve.Equal(tt.expectedReserve) {
				t.Fatalf("Unexpected pool.reserve: got %v want %v", pool.reserve, tt.expectedReserve)
			}
		})
	}
}

func TestIPPoolFunctionality(t *testing.T) {
	pool := populateIPPoolCap4(t)

	domain_3 := "3.example.com"
	domain_4 := "4.example.com"
	domain_5 := "5.example.com"
	domain_6 := "6.example.com"
	domain_another := "another.example.com"
	ip_outside := net.ParseIP("10.0.0.1")

	// Allocate and lock domain_3
	ip4_3, ip6_3, err := pool.Resolve(domain_3)
	if err != nil || ip4ToIdx(ip4_3, pool.cidr) != 3 || ip6ToIdx(ip6_3, pool.cidr6) != 3 {
		t.Fatalf("Resolve failed: %v, domain: %v, ip4: %v, ip6: %v", err, domain_3, ip4_3, ip6_3)
	}
	fqdn_3, ref_3, err := pool.RevResolveAndRef(ip4_3)
	if err != nil || fqdn_3 != domain_3 {
		t.Fatalf("RevResolveAndRef failed: %v, ip4: %v, fqdn: %v", err, ip4_3, fqdn_3)
	}
	fqdn_3_v6, ref_3_v6, err := pool.RevResolveAndRef(ip6_3)
	if err != nil || fqdn_3_v6 != domain_3 {
		t.Fatalf("RevResolveAndRef failed: %v, ip6: %v, fqdn: %v", err, ip6_3, fqdn_3_v6)
	}

	// Attempt to query unallocated and out-of-pool IPs
	_, _, err = pool.RevResolveAndRef(idxToIp4(4, pool.cidr6))
	if err == nil {
		t.Fatalf("RevResolveAndRef should have failed for IP not allocated")
	}
	_, _, err = pool.RevResolveAndRef(ip_outside)
	if err == nil {
		t.Fatalf("RevResolveAndRef should have failed for IP outside pool")
	}

	// Allocate and lock domain_4, domain_5, domain_6
	ip4_4, ip6_4, err := pool.Resolve(domain_4)
	if err != nil || ip4ToIdx(ip4_4, pool.cidr) != 4 || ip6ToIdx(ip6_4, pool.cidr6) != 4 {
		t.Fatalf("Resolve failed: %v, domain: %v, ip4: %v, ip6: %v", err, domain_4, ip4_4, ip6_4)
	}
	fqdn_4, ref_4, err := pool.RevResolveAndRef(ip4_4)
	if err != nil || fqdn_4 != domain_4 {
		t.Fatalf("RevResolveAndRef failed: %v, ip4: %v, fqdn: %v", err, ip4_4, fqdn_4)
	}
	ip4_5, ip6_5, err := pool.Resolve(domain_5)
	if err != nil || ip4ToIdx(ip4_5, pool.cidr) != 5 || ip6ToIdx(ip6_5, pool.cidr6) != 5 {
		t.Fatalf("Resolve failed: %v, domain: %v, ip4: %v, ip6: %v", err, domain_5, ip4_5, ip6_5)
	}
	fqdn_5, ref_5, err := pool.RevResolveAndRef(ip4_5)
	if err != nil || fqdn_5 != domain_5 {
		t.Fatalf("RevResolveAndRef failed: %v, ip4: %v, fqdn: %v", err, ip4_5, fqdn_5)
	}
	ip4_6, ip6_6, err := pool.Resolve(domain_6)
	if err != nil || ip4ToIdx(ip4_6, pool.cidr) != 6 || ip6ToIdx(ip6_6, pool.cidr6) != 6 {
		t.Fatalf("Resolve failed: %v, domain: %v, ip4: %v, ip6: %v", err, domain_6, ip4_6, ip6_6)
	}
	fqdn_6, ref_6, err := pool.RevResolveAndRef(ip4_6)
	if err != nil || fqdn_6 != domain_6 {
		t.Fatalf("RevResolveAndRef failed: %v, ip4: %v, fqdn: %v", err, ip4_6, fqdn_6)
	}

	// Attempt to allocate when pool is exhausted
	_, _, err = pool.Resolve(domain_another)
	if err == nil {
		t.Fatalf("Resolve should have failed when pool is exhausted")
	}
	_, _, err = pool.Resolve(domain_3)
	if err != nil {
		t.Fatalf("Resolve should have succeeded for already allocated domain: %v", err)
	}

	// Release resource
	ref_4.deref()
	ip4_another, ip6_another, err := pool.Resolve(domain_another)
	if err != nil || !ip4_another.Equal(ip4_4) || !ip6_another.Equal(ip6_4) {
		t.Fatalf("Resolve failed: %v, domain: %v, ip4: %v, ip6: %v", err, domain_another, ip4_another, ip6_another)
	}

	ref_3.deref()
	ref_3_v6.deref()
	ref_5.deref()
	ref_6.deref()
}
