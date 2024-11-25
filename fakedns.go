package main

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"github.com/deckarep/golang-set"
	"github.com/miekg/dns"
	"log/slog"
	"net"
)

type IPPool struct {
	cidr    net.IPNet
	cidr6   net.IPNet
	size    uint32
	current uint32
	reserve mapset.Set

	n2i      map[string]uint32
	i2n      map[uint32]string
	fqdnList list.List
}

func NewIPPool(cidr net.IPNet, reserveIp net.IP, cidr6 net.IPNet, reserveIp6 net.IP) *IPPool {
	// process available ip space
	ones, bits := cidr.Mask.Size()
	space := bits - ones
	ones6, bits6 := cidr6.Mask.Size()
	space6 := bits6 - ones6
	if space6 < space {
		space = space6
	}
	size := uint32(1 << uint(space))
	if size == 0 {
		size--
	}

	if ones6 < 128-32 {
		cidr6.Mask = net.CIDRMask(128-32, 128)
	}

	// exclude special ip addresses
	reserve := mapset.NewSet()
	reserve.Add(0)
	reserve.Add(size - 1)
	reserve.Add(ip4ToIdx(reserveIp, cidr))
	if cidr6.Contains(reserveIp6) {
		reserve.Add(ip6ToIdx(reserveIp6, cidr6))
	}

	pool := &IPPool{
		cidr:     cidr,
		cidr6:    cidr6,
		size:     size,
		current:  0,
		reserve:  reserve,
		n2i:      make(map[string]uint32),
		i2n:      make(map[uint32]string),
		fqdnList: *list.New(),
	}
	return pool
}

func (p *IPPool) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question {
		fqdn := question.Name
		ip4, ip6 := p.Resolve(fqdn)
		slog.Debug("[FakeDNS] resolve:", "fqdn", fqdn, "ip4", ip4, "ip6", ip6)
		if question.Qtype == dns.TypeA {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}
			rr.A = ip4
			msg.Answer = append(msg.Answer, rr)
		} else if question.Qtype == dns.TypeAAAA {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0}
			rr.AAAA = ip6
			msg.Answer = append(msg.Answer, rr)
		} else {
			// ignore other types
		}
	}
	_ = w.WriteMsg(msg)
}

func (p *IPPool) Alloc(fqdn string) uint32 {
	p.fqdnList.PushBack(fqdn)
	for {
		if p.current >= p.size {
			// replace one
			victim := p.fqdnList.Front().Value.(string)
			victimIdx := p.n2i[victim]
			p.fqdnList.Remove(p.fqdnList.Front())
			slog.Debug("[FakeDNS] replace:", "victim", victim, "index", victimIdx)

			delete(p.n2i, victim)
			p.n2i[fqdn] = victimIdx
			p.i2n[victimIdx] = fqdn
			return victimIdx
		} else {
			p.current++
			if p.reserve.Contains(p.current) {
				slog.Debug("[FakeDNS] skip index:", "index", p.current)
				continue
			}
			p.n2i[fqdn] = p.current
			p.i2n[p.current] = fqdn
			return p.current
		}
	}
}

func (p *IPPool) Resolve(fqdn string) (net.IP, net.IP) {
	if idx, ok := p.n2i[fqdn]; ok {
		return p.idx2ip(idx)
	} else {
		idx := p.Alloc(fqdn)
		slog.Debug("[FakeDNS] allocate:", "fqdn", fqdn, "index", idx)
		return p.idx2ip(idx)
	}
}

func (p *IPPool) RevResolve(ip net.IP) (string, error) {
	if p.Contains(ip) {
		idx := p.ip2idx(ip)
		return p.i2n[idx], nil
	}
	return "", fmt.Errorf("IP not in pool")
}

func (p *IPPool) Contains(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return p.cidr.Contains(ip4)
	}
	return p.cidr6.Contains(ip)
}

func (p *IPPool) ip2idx(ip net.IP) uint32 {
	if ip4 := ip.To4(); ip4 != nil {
		return binary.BigEndian.Uint32(ip4) - binary.BigEndian.Uint32(p.cidr.IP)
	}
	return binary.BigEndian.Uint32(ip[12:]) - binary.BigEndian.Uint32(p.cidr6.IP[12:])
}

func (p *IPPool) idx2ip(idx uint32) (net.IP, net.IP) {
	return idxToIp4(idx, p.cidr), idxToIp6(idx, p.cidr6)
}

func ip4ToIdx(ip net.IP, cidr net.IPNet) uint32 {
	return binary.BigEndian.Uint32(ip) - binary.BigEndian.Uint32(cidr.IP)
}

func idxToIp4(idx uint32, cidr net.IPNet) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(cidr.IP)+idx)
	return ip
}

func ip6ToIdx(ip net.IP, cidr net.IPNet) uint32 {
	return binary.BigEndian.Uint32(ip[12:]) - binary.BigEndian.Uint32(cidr.IP[12:])
}

func idxToIp6(idx uint32, cidr net.IPNet) net.IP {
	ip := make(net.IP, net.IPv6len)
	copy(ip, cidr.IP)
	binary.BigEndian.PutUint32(ip[12:], binary.BigEndian.Uint32(cidr.IP[12:])+idx)
	return ip
}
