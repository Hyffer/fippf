package main

import (
	"bufio"
	"fmt"
	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

func SetNetworkChangeHandler(callback func()) {
	// trigger to invoke callback
	update := make(chan struct{}, 1)

	go func() {
		for {
			<-update
			time.Sleep(10 * time.Second) // wait for network go stable
			callback()
		}
	}()

	// using timer to handle some corner cases when dns changes with no network event
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			select {
			case update <- struct{}{}:
			default:
			}
		}
	}()

	// listen to network change event
	go func() {
		for {
			conf := &netlink.Config{
				Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE,
			}
			watchConn, err := netlink.Dial(unix.NETLINK_ROUTE, conf)
			if err != nil {
				slog.Error("[RTNETLINK] Failed to dial netlink socket, "+
					"this might cause DNS change not being detected timely.", "err", err)
				return
			}
			for {
				raw, err := watchConn.Receive()
				if err != nil {
					slog.Error("[RTNETLINK] Netlink error when receiving.", "err", err)
					break
				}
				for _, msg := range raw {
					switch msg.Header.Type {
					case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
						rmsg := rtnetlink.RouteMessage{}
						err = rmsg.UnmarshalBinary(msg.Data)
						if err != nil {
							slog.Error("[RTNETLINK] Failed to unmarshal route message:", "err", err)
							continue
						}
						action := ""
						if msg.Header.Type == unix.RTM_NEWROUTE {
							action = "add"
						} else {
							action = "del"
						}
						dst := rmsg.Attributes.Dst
						src := rmsg.Attributes.Src
						gw := rmsg.Attributes.Gateway
						slog.Debug("[RTNETLINK] Route "+action+":", "dst", dst, "src", src, "gw", gw)
						if action == "add" && dst == nil {
							// default route added
							select {
							case update <- struct{}{}:
							default:
							}
						}
					default:
						lmsg := rtnetlink.LinkMessage{}
						err = lmsg.UnmarshalBinary(msg.Data)
						if err != nil {
							slog.Error("[RTNETLINK] Failed to unmarshal link message:", "err", err)
							continue
						}
						iface := lmsg.Attributes.Name
						state := lmsg.Attributes.OperationalState
						slog.Debug("[RTNETLINK] Interface state changed:", "iface", iface, "state", state)
						if lmsg.Attributes.OperationalState == rtnetlink.OperStateUp {
							select {
							case update <- struct{}{}:
							default:
							}
						}
					} // switch msg.Header.Type
				} // for _, msg := range raw

			} // receiving loop
			_ = watchConn.Close()
			slog.Warn("[RTNETLINK] listener exited, restarting in 10 seconds.")
			time.Sleep(10 * time.Second)
		}
	}()
}

func GetUpstreamDNS() []string {
	iface, err := getDefaultInterface()
	if err != nil {
		slog.Error("[DNS UPSTREAM] Failed to get default route interface", "err", err)
		return nil
	}
	slog.Info("[DNS UPSTREAM] System default route interface", "name", iface)

	validIPs := func(ss []string) []string {
		ips := make([]string, 0, len(ss))
		for _, s := range ss {
			ip := net.ParseIP(s)
			if ip == nil {
				slog.Error("[DNS UPSTREAM] Failed to parse DNS IP, "+
					"this may caused by incorrectly parsed command output.", "invalid_IP", s)
				continue
			}
			if ip.To4() == nil {
				slog.Warn("[DNS UPSTREAM] Currently only support IPv4 DNS, ignoring", "dns", s)
				continue
			}
			ips = append(ips, s)
		}
		return ips
	}

	// Try to get DNS from NetworkManager and networkd
	dns, err := getDNSFromNM(iface)
	if err == nil {
		ips := validIPs(dns)
		if len(ips) != 0 {
			return ips
		}
	}
	slog.Info("[DNS UPSTREAM] Failed to get DNS from NetworkManager", "err", err)

	dns, err = getDNSFromNetworkd(iface)
	if err == nil {
		ips := validIPs(dns)
		if len(ips) != 0 {
			return ips
		}
	}
	slog.Info("[DNS UPSTREAM] Failed to get DNS from networkd", "err", err)
	return nil
}

// refer to: https://github.com/nixigaj/go-default-route/blob/master/defaultroute_linux.go
func getDefaultInterface() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line)
		// Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
		iface := fields[0]
		dst := fields[1]
		mask := fields[7]

		if strings.HasPrefix(iface, "lo") || strings.HasPrefix(iface, "tun") ||
			strings.HasPrefix(iface, "wg") || strings.HasPrefix(iface, "tailscale") {
			continue
		}
		if dst == "00000000" && mask == "00000000" {
			// default route
			return iface, nil
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("default route interface not found")
}

func getDNSFromNetworkd(iface string) ([]string, error) {
	cmd := exec.Command("networkctl", "--no-pager", "--full", "status", iface)
	sBuilder := new(strings.Builder)
	cmd.Stdout = sBuilder
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("networkctl execution failed: %w", err)
	}
	// output example:
	// DNS: xxx.xxx.xxx.xxx
	//      xxx.xxx.xxx.xxx
	output := sBuilder.String()

	re := regexp.MustCompile(`DNS:((?:\s*(?:[0-9.]*|[0-9a-fA-F:]*)\s*)+)`) // extract DNS part
	str := re.FindStringSubmatch(output)
	if len(str) < 2 {
		return nil, fmt.Errorf("failed to extract DNS from networkctl output.\n"+
			"command: %s\noutput: %s", cmd.String(), output)
	}
	dns := strings.Fields(str[1])
	slog.Debug("[DNS UPSTREAM] Get upstream DNS from networkd:", "dns", dns)
	return dns, nil
}

func getDNSFromNM(iface string) ([]string, error) {
	cmd := exec.Command("nmcli", "--terse", "device", "show", iface)
	sBuilder := new(strings.Builder)
	cmd.Stdout = sBuilder
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("nmcli execution failed: %w", err)
	}
	// output example:
	// IP4.DNS[1]:xxx.xxx.xxx.xxx
	// IP4.DNS[2]:xxx.xxx.xxx.xxx
	output := sBuilder.String()

	re := regexp.MustCompile(`IP[46]\.DNS\[\d+]:\s*(\S+)`)
	matches := re.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("failed to extract DNS from nmcli output.\n"+
			"command: %s\noutput: %s", cmd.String(), output)
	}
	dns := make([]string, 0, len(matches))
	for _, match := range matches {
		dns = append(dns, match[1])
	}
	slog.Debug("[DNS UPSTREAM] Get upstream DNS from NetworkManager:", "dns", dns)
	return dns, nil
}
