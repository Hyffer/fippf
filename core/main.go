package core

import (
	"errors"
	"github.com/0990/socks5"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path"
	"strconv"
	"syscall"
	"time"
)

func Launch(configDir string, sockFile string) {
	// Configurations definition
	viper.SetDefault("if_name", "tun0")
	viper.SetDefault("mtu", 1500)
	viper.SetDefault("ip_range", "198.18.0.1/16")
	viper.SetDefault("ip6_range", "fc00:fdfe::1/96")

	viper.SetDefault("dns_listen", "127.0.0.52")
	viper.SetDefault("dns_port", 53)

	viper.SetDefault("proxy", "127.0.0.1:8001")

	viper.SetDefault("udp_timeout", 30)
	viper.SetDefault("tcp_timeout", 600)

	viper.SetDefault("geosite_file", "./dlc.dat")
	viper.SetDefault("dns_group", map[string][]string{"default": {"8.8.8.8", "223.5.5.5"}})

	viper.AddConfigPath(configDir)
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	err := viper.ReadInConfig()
	if err != nil {
		slog.Warn("Cannot read config file:", "err", err)
	}
	viper.SetConfigName("dns_rule")
	_ = viper.MergeInConfig()

	slog.Info("Set", "log_level", viper.GetString("log_level"))
	switch viper.GetString("log_level") {
	case "debug":
		slog.SetLogLoggerLevel(slog.LevelDebug)
	case "info":
		slog.SetLogLoggerLevel(slog.LevelInfo)
	case "warn":
		slog.SetLogLoggerLevel(slog.LevelWarn)
	case "error":
		slog.SetLogLoggerLevel(slog.LevelError)
	default:
		slog.Warn("Unknown log level, defaulting to info")
	}

	// Create TUN interface
	tunIf, err := NewTunIf(
		viper.GetString("if_name"), viper.GetUint32("mtu"),
		viper.GetString("ip_range"), viper.GetString("ip6_range"),
	)
	if err != nil {
		slog.Error("Failed to create TUN interface:", "err", err)
		os.Exit(1)
	}
	defer tunIf.Close()

	// Fake-IP DNS server
	pool := NewIPPool(tunIf.cidr, tunIf.ip, tunIf.cidr6, tunIf.ip6)

	dnsRule := &[]DNSRule{}
	if viper.InConfig("dns_rule") {
		err = viper.UnmarshalKey("dns_rule", dnsRule)
		if err != nil {
			slog.Error("Unmarshal DNS rule failed:", "err", err)
		}
	} else {
		slog.Warn("No DNS rule found in config file")
	}

	geosite_file := viper.GetString("geosite_file")
	if !path.IsAbs(geosite_file) {
		geosite_file = path.Join(configDir, geosite_file)
	}

	dnsHdlr, err := NewDNSHandler(
		dnsRule, geosite_file, pool,
		viper.GetStringMapStringSlice("dns_group"),
	)
	if err != nil {
		slog.Error("Failed to create DNS handler:", "err", err)
		os.Exit(1)
	}

	dnsSrv := &dns.Server{
		Addr:    viper.GetString("dns_listen") + ":" + strconv.Itoa(viper.GetInt("dns_port")),
		Net:     "udp",
		Handler: dnsHdlr,
		UDPSize: 65535,
	}
	defer func(dnsSrv *dns.Server) {
		_ = dnsSrv.Shutdown()
	}(dnsSrv)

	go func() {
		err := dnsSrv.ListenAndServe()
		if err != nil {
			slog.Error("Failed to start DNS server:", "err", err)
			os.Exit(1)
		}
	}()

	// Proxy backend
	proxyBE := viper.GetString("proxy")
	slog.Info("Using proxy backend", "socks5", proxyBE)
	proxyDialer := socks5.NewSocks5Client(socks5.ClientCfg{ServerAddr: proxyBE})

	tcpTimeout := viper.GetInt("tcp_timeout")
	udpTimeout := viper.GetInt("udp_timeout")
	if udpTimeout <= 0 {
		slog.Warn("UDP timeout is disabled, this may cause resource exhaustion")
	}

	// main handler
	tunIf.SetConnHandler(func(t uint32, acceptor ConnAcceptor, dst netip.AddrPort) {
		fqdn, ref, err := pool.RevResolveAndRef(dst.Addr().AsSlice())
		if err != nil {
			slog.Error("Failed to resolve FQDN:", "err", err, "ip", dst.Addr())
			acceptor.deny()
			return
		}
		defer ref.deref()
		realDst := net.JoinHostPort(fqdn, strconv.Itoa(int(dst.Port())))

		conn, err := acceptor.accept()
		if err != nil {
			slog.Error("Failed to establish connection from client:", "err", err)
			return
		}

		slog.Debug("Accepted", "from", conn.RemoteAddr(), "to", conn.LocalAddr(), "fqdn", fqdn)

		var timeout int
		var network string
		switch t {
		case tcpProtocolNumber:
			network = "tcp"
			timeout = tcpTimeout
		case udpProtocolNumber:
			network = "udp"
			timeout = udpTimeout
		default:
			slog.Error("Unexpected error: unknown protocol number:", "t", t)
		}

		proxyConn, err := proxyDialer.DialTimeout(network, realDst, time.Second)
		if err != nil {
			slog.Error("Failed to dial through proxy:", "err", err)
			_ = conn.Close()
			return
		}

		relayWithIdleTimeout(conn, proxyConn, timeout) // block until relay exits
	})

	go RunInspector(sockFile)

	slog.Info("FIPPF started")

	termChan := make(chan os.Signal)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)

	<-termChan
	slog.Info("Quit")
}

func relayWithIdleTimeout(conn net.Conn, proxyConn net.Conn, timeout int) {
	defer func() {
		_ = conn.Close()
		_ = proxyConn.Close()
	}()

	c := make(chan int64, 2)

	relay := func(src net.Conn, dst net.Conn) {
		// src and dst both have deadline set.
		// one of them is gonet.TCPConn/UDPConn created from gvisor netstack,
		// which timeout handling is slightly different
		n, err := io.Copy(dst, src)
		if err != nil {
			netOpErr := &net.OpError{}
			switch {
			case errors.Is(err, os.ErrDeadlineExceeded):
				c <- n
			case errors.As(err, &netOpErr):
				// gonet has its own unexported error type `timeoutError` for timeout
				// see gvisor/pkg/tcpip/adapters/gonet/gonet.go
				if (err.(*net.OpError)).Timeout() {
					c <- n
				} else {
					c <- -1 // non-timeout error
				}
			default:
				c <- -1 // non-timeout error
			}
		} else {
			c <- -1 // TCP socket closed
		}
	}

	for {
		if timeout > 0 {
			err := conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
			if err != nil {
				slog.Error("Failed to set deadline for connection:", "conn", conn, "err", err)
				return
			}
			err = proxyConn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
			if err != nil {
				slog.Error("Failed to set deadline for connection:", "proxyConn", proxyConn, "err", err)
				return
			}
		}
		go relay(conn, proxyConn)
		go relay(proxyConn, conn)
		// gather relays' status of current epoch:
		// a negative number means connection closed or error occurred, no need to continue relaying.
		// a non-negative number means number of bytes transferred on one direction.
		n1 := <-c
		if n1 < 0 {
			// either direction of relay ends or error occurs
			return
		}
		n2 := <-c
		if n2 < 0 || (n1 == 0 && n2 == 0) {
			return
		}
	}
}
