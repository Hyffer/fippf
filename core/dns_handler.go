package core

import (
	"fmt"
	"github.com/metacubex/geo/geosite"
	"github.com/miekg/dns"
	"log/slog"
	"regexp"
	"slices"
	"sync/atomic"
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
	dnsUpstream *atomic.Value
	dnsGroup    map[string][]string
}

func NewDNSHandler(rule *[]DNSRule, geosite_file string, ipPool *IPPool, dnsGroup map[string][]string) (*DNSHandler, error) {
	geoSite, err := geosite.FromFile(geosite_file)
	if err != nil {
		return nil, fmt.Errorf("failed to load geosite file: %w", err)
	}

	if dnsGroup == nil || dnsGroup["default"] == nil || len(dnsGroup["default"]) == 0 {
		return nil, fmt.Errorf("default dns group not exist or empty")
	}

	dnsUpstream := &atomic.Value{}
	dnsUpstream.Store([]string{})
	updateDNSUpstream := func() {
		newVal := GetUpstreamDNS()
		if newVal == nil || len(newVal) == 0 {
			newVal = dnsGroup["default"]
		}
		slog.Debug("[DNS Handler] Upstream DNS servers", "ip", newVal)
		oldVal := dnsUpstream.Load().([]string)
		if !slices.Equal(oldVal, newVal) {
			slog.Info("[DNS Handler] Update upstream DNS servers", "from", oldVal, "to", newVal)
			dnsUpstream.Store(newVal)
		}
	}
	updateDNSUpstream()
	SetNetworkChangeHandler(updateDNSUpstream)

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
	if r.RecursionDesired {
		msg.RecursionAvailable = true
	}

	if r.Opcode != dns.OpcodeQuery || len(r.Question) == 0 {
		msg.SetRcode(r, dns.RcodeNotImplemented)
		slog.Debug("[DNS Handler] Reject for not implemented. Rare dns packet", "from", w.RemoteAddr(),
			"opcode", dns.OpcodeToString[r.Opcode], "qdcount", len(r.Question))

	} else if len(r.Question) > 1 {
		// In consideration of RFC 9619 https://datatracker.ietf.org/doc/rfc9619/,
		// and most of the DNS servers actually do not support this https://maradns.samiam.org/multiple.qdcount.html
		msg.SetRcode(r, dns.RcodeFormatError)
		slog.Debug("[DNS Handler] Reject for incorrect format. "+
			"Multiple questions in one query, this might be a client side error.", "client", w.RemoteAddr())

	} else {
		// well-formed standard query
		question := r.Question[0]
		fqdn := question.Name

		if question.Qclass == dns.ClassINET && (question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA) {
			// split dns query by custom rule
			resolver := handler.MatchRule(fqdn)
			switch resolver {
			case "fakeip":
				ip4, ip6, err := handler.ipPool.Resolve(fqdn)
				if err != nil {
					slog.Warn("[DNS Handler] Fake IP resolve failed:", "fqdn", fqdn, "err", err)
					msg.SetRcode(r, dns.RcodeServerFailure)
					break
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
				msg = DNSQuery(r, handler.dnsUpstream.Load().([]string))
			case "block":
			default:
				re, _ := regexp.Compile("grp_(.+)")
				matches := re.FindStringSubmatch(resolver)
				if matches != nil && len(matches) == 2 {
					// pass through to dns group
					group := matches[1]
					msg = handler.DNSPassThrough(r, group)

				} else {
					slog.Error("[DNS Handler] Unexpected:", "resolver", resolver)
				}
			}

		} else {
			// pass through query types other than A and AAAA
			slog.Debug("[DNS Handler] Pass through dns query that fake-IP DNS does not handle:", "fqdn", fqdn,
				"qtype", dns.TypeToString[question.Qtype], "qclass", dns.ClassToString[question.Qclass])
			msg = DNSQuery(r, handler.dnsUpstream.Load().([]string))
		}
	}

	if msg != nil {
		_ = w.WriteMsg(msg)
	}
}

func (handler *DNSHandler) DNSPassThrough(req *dns.Msg, group string) *dns.Msg {
	ips, ok := handler.dnsGroup[group]
	if !ok {
		slog.Error("[DNS Handler] DNS group not found:", "group", group)
		return nil
	}
	return DNSQuery(req, ips)
}

func DNSQuery(req *dns.Msg, serverIPs []string) *dns.Msg {
	c := &dns.Client{Timeout: 1 * time.Second}
	var succResp, lastResp *dns.Msg = nil, nil
	for _, serverIP := range serverIPs {
		resp, _, err := c.Exchange(req, serverIP+":53")
		if err != nil || resp == nil {
			continue
		}
		lastResp = resp
		if resp.Rcode != dns.RcodeSuccess {
			continue
		}
		succResp = resp
		break
	}

	if lastResp == nil {
		slog.Error("[DNS Handler] None of those servers gives an answer", "servers", serverIPs)
		return nil
	}
	if succResp == nil {
		succResp = lastResp
	}
	return succResp
}
