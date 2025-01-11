package main

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"github.com/deckarep/golang-set"
	"github.com/miekg/dns"
	"log/slog"
	"net"
	"sync"
)

type Ref struct {
	deref func()
}

type Mapping struct {
	idx      uint32
	fqdn     string
	useCount int           // number of relays opening on this mapping
	ptr      *list.Element // points to the element of itself if in the victim list, nil otherwise
}

type IPPool struct {
	sync.Mutex
	cidr    net.IPNet
	cidr6   net.IPNet
	size    uint32
	current uint32
	reserve mapset.Set

	n2m     map[string]*Mapping
	i2m     map[uint32]*Mapping
	victims *list.List
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
		cidr:    cidr,
		cidr6:   cidr6,
		size:    size,
		current: 0,
		reserve: reserve,
		n2m:     make(map[string]*Mapping),
		i2m:     make(map[uint32]*Mapping),
		victims: list.New(),
	}
	return pool
}

func (p *IPPool) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question {
		fqdn := question.Name
		ip4, ip6, err := p.Resolve(fqdn)
		if err != nil {
			msg.SetRcode(r, dns.RcodeServerFailure)
			slog.Warn("[FakeDNS] failed to resolve:", "fqdn", fqdn, "err", err)
		} else {
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
	}
	_ = w.WriteMsg(msg)
}

func (p *IPPool) Alloc(fqdn string) (uint32, error) {
	for {
		if p.current >= p.size-1 {
			// replace one
			if p.victims.Len() == 0 {
				return 0, fmt.Errorf("no available IP to recycle for allocation")
			}
			victim := p.victims.Front()
			p.victims.MoveToBack(victim)
			mapping := victim.Value.(*Mapping)
			slog.Debug("[FakeDNS] replace:", "victim-fqdn", mapping.fqdn, "victim-index", mapping.idx)

			delete(p.n2m, mapping.fqdn)
			p.n2m[fqdn] = mapping
			mapping.fqdn = fqdn
			return mapping.idx, nil
		} else {
			p.current++
			if p.reserve.Contains(p.current) {
				slog.Debug("[FakeDNS] skip index:", "index", p.current)
				continue
			}
			mapping := &Mapping{
				idx:      p.current,
				fqdn:     fqdn,
				useCount: 0,
			}
			mapping.ptr = p.victims.PushBack(mapping)
			p.n2m[fqdn] = mapping
			p.i2m[p.current] = mapping
			return p.current, nil
		}
	}
}

func (p *IPPool) Resolve(fqdn string) (ip4 net.IP, ip6 net.IP, err error) {
	p.Lock()
	defer p.Unlock()
	if mapping, ok := p.n2m[fqdn]; ok {
		ip4, ip6 = p.idx2ip(mapping.idx)
		err = nil
		return
	} else {
		idx, e := p.Alloc(fqdn)
		if e != nil {
			return nil, nil, fmt.Errorf("failed to allocate fake IP: %w", e)
		}
		slog.Debug("[FakeDNS] allocate:", "fqdn", fqdn, "index", idx)
		ip4, ip6 = p.idx2ip(idx)
		err = nil
		return
	}
}

func (p *IPPool) RevResolveAndRef(ip net.IP) (string, *Ref, error) {
	p.Lock()
	defer p.Unlock()
	if p.Contains(ip) {
		idx := p.ip2idx(ip)
		if mapping, ok := p.i2m[idx]; ok {
			mapping.useCount++
			if mapping.ptr != nil {
				p.victims.Remove(mapping.ptr) // remove from victim list, lock this mapping
				mapping.ptr = nil
			}
			slog.Debug("[FakeDNS] rev-resolve and ref:",
				"fake-ip", ip, "fqdn", mapping.fqdn, "use-count", mapping.useCount)
			ref := &Ref{deref: func() {
				p.Lock()
				defer p.Unlock()
				if mapping.useCount > 0 {
					mapping.useCount--
					if mapping.useCount == 0 {
						mapping.ptr = p.victims.PushBack(mapping)
					}
					slog.Debug("[FakeDNS] deref:",
						"fake-ip", ip, "fqdn", mapping.fqdn, "use-count", mapping.useCount)
				} else {
					slog.Error("This should not happen: Deref but useCount not positive:",
						"fake-ip", ip)
				}
			}}
			return mapping.fqdn, ref, nil
		}
		return "", nil, fmt.Errorf("no matching fqdn of requested IP")
	}
	return "", nil, fmt.Errorf("IP not in pool")
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
