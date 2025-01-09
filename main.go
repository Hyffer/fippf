package main

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/txthinking/socks5"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	pflag.String("config_dir", "/etc/fippf", "config directory")
	pflag.String("log_level", "info", "one of debug, info, warn, error")
	pflag.Parse()

	_ = viper.BindPFlag("log_level", pflag.Lookup("log_level"))

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

	viper.AddConfigPath(pflag.Lookup("config_dir").Value.String())
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	err := viper.ReadInConfig()
	if err != nil {
		slog.Warn("Cannot read config file:", "err", err)
	}

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
	dnsSrv := &dns.Server{
		Addr:    viper.GetString("dns_listen") + ":" + strconv.Itoa(viper.GetInt("dns_port")),
		Net:     "udp",
		Handler: pool,
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
	// socks5 in go library does not support UDP
	// but this one does not support dial timeout todo
	proxyDialer, err := socks5.NewClient(proxyBE, "", "", 0, 0)
	if err != nil {
		slog.Error("Failed to construct proxy dialer:", "err", err)
		os.Exit(1)
	}

	tcpTimeout := viper.GetInt("tcp_timeout")
	udpTimeout := viper.GetInt("udp_timeout")
	if udpTimeout <= 0 {
		slog.Warn("UDP timeout is disabled, this may cause resource exhaustion")
	}

	// main handler
	tunIf.SetConnHandler(func(t uint32, acceptor ConnAcceptor, dst netip.AddrPort) {
		fqdn, err := pool.RevResolve(dst.Addr().AsSlice())
		if err != nil {
			slog.Error("Failed to resolve FQDN:", "err", err, "ip", dst.Addr())
			acceptor.deny()
			return
		}
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

		proxyConn, err := proxyDialer.Dial(network, realDst)
		if err != nil {
			slog.Error("Failed to dial through proxy:", "err", err)
			_ = conn.Close()
			return
		}

		go relayWithIdleTimeout(conn, proxyConn, timeout)
	})

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
		n2 := <-c
		if n1 < 0 || n2 < 0 || (n1 == 0 && n2 == 0) {
			return
		}
	}
}
