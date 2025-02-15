package main

import (
	"fmt"
	"github.com/metacubex/geo/geosite"
	"github.com/miekg/dns"
	"log/slog"
	"regexp"
	"slices"
	"time"
)

type DNSRule struct {
	// matcher
	Regex   string `mapstructure:"regex"`
	GeoSite string `mapstructure:"geosite"`
	// resolver
	Resolver string `mapstructure:"resolver"`
}

type DNSHandler struct {
	rule        *[]DNSRule
	geoSite     *geosite.Database
	ipPool      *IPPool
	dnsUpstream []string
	dnsGroup    map[string][]string
}

func NewDNSHandler(rule *[]DNSRule, geosite_file string, ipPool *IPPool, dnsGroup map[string][]string) (*DNSHandler, error) {
	geoSite, err := geosite.FromFile(geosite_file)
	if err != nil {
		return nil, fmt.Errorf("failed to load geosite file: %w", err)
	}
	dnsUpstream := GetUpstreamDNS()
	if dnsUpstream == nil || len(dnsUpstream) == 0 {
		dnsUpstream = dnsGroup["default"]
	}
	slog.Info("[DNS Handler] Upstream DNS servers", "ip", dnsUpstream)
	return &DNSHandler{
		rule:        rule,
		geoSite:     geoSite,
		ipPool:      ipPool,
		dnsUpstream: dnsUpstream,
		dnsGroup:    dnsGroup,
	}, nil
}

func (handler *DNSHandler) MatchRule(fqdn string) string {
	domain := fqdn
	if len(domain) > 0 && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1] // remove trailing dot
	}
	for _, rule := range *handler.rule {
		if rule.Regex != "" {
			regMatch, _ := regexp.Match(rule.Regex, []byte(domain))
			if !regMatch {
				continue
			}
		}
		if rule.GeoSite != "" {
			codes := handler.geoSite.LookupCodes(domain)
			geoMatch := slices.Contains(codes, rule.GeoSite)
			if !geoMatch {
				continue
			}
		}
		slog.Debug("[DNS Handler] Rule matched", "domain", domain, "rule", rule)
		return rule.Resolver
	}
	slog.Debug("[DNS Handler] No rule matched, fallback to fakeip", "domain", domain)
	return "fakeip"
}

func (handler *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	if r.RecursionDesired {
		msg.RecursionAvailable = true
	}

	for _, question := range r.Question {
		fqdn := question.Name

		if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
			// split dns query by custom rule
			resolver := handler.MatchRule(fqdn)
			switch resolver {
			case "fakeip":
				ip4, ip6, err := handler.ipPool.Resolve(fqdn)
				if err != nil {
					slog.Warn("[DNS Handler] Fake IP resolve failed:", "fqdn", fqdn, "err", err)
					continue
				}
				slog.Debug("[DNS Handler] Fake IP resolve:", "fqdn", fqdn, "ip4", ip4, "ip6", ip6)
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
				}
			case "upstream":
				msg.Answer = append(msg.Answer, DNSQuery(fqdn, question.Qtype, handler.dnsUpstream)...)
			case "block":
			default:
				re, _ := regexp.Compile("grp_(.+)")
				matches := re.FindStringSubmatch(resolver)
				if matches != nil && len(matches) == 2 {
					// pass through to dns group
					group := matches[1]
					msg.Answer = append(msg.Answer, handler.DNSPassThrough(fqdn, question.Qtype, group)...)

				} else {
					slog.Error("[DNS Handler] Unexpected:", "resolver", resolver)
				}
			}

		} else {
			// pass through query types other than A and AAAA
			msg.Answer = append(msg.Answer, DNSQuery(fqdn, question.Qtype, handler.dnsUpstream)...)
		}
	}
	_ = w.WriteMsg(msg)
}

func (handler *DNSHandler) DNSPassThrough(fqdn string, qtype uint16, group string) []dns.RR {
	ips, ok := handler.dnsGroup[group]
	if !ok {
		slog.Error("[DNS Handler] DNS group not found:", "group", group)
		return nil
	}
	slog.Debug("[DNS Handler] Pass through query:", "fqdn", fqdn, "qtype", dns.TypeToString[qtype], "group", group)
	return DNSQuery(fqdn, qtype, ips)
}

func DNSQuery(domain string, qtype uint16, serverIPs []string) []dns.RR {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	c := &dns.Client{Timeout: 1 * time.Second}
	response := new(dns.Msg)
	response = nil
	for _, serverIP := range serverIPs {
		resp, _, err := c.Exchange(m, serverIP+":53")
		if err != nil ||
			resp == nil ||
			resp.Rcode != dns.RcodeSuccess {
			continue
		}
		response = resp
		break
	}

	if response == nil {
		slog.Error("[DNS Handler] None of those servers gives an answer", "servers", serverIPs)
		return nil
	}
	return response.Answer
}
