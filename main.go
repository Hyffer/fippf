package main

import (
	"github.com/miekg/dns"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/net/proxy"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
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
	tcpDialer, err := proxy.SOCKS5("tcp", proxyBE, nil, proxy.Direct)
	if err != nil {
		slog.Error("Failed to construct proxy dialer:", "err", err)
		os.Exit(1)
	}

	// main handler
	tunIf.SetConnHandler(func(t uint32, conn net.Conn) {
		switch t {
		case tcpProtocolNumber:
			slog.Debug("TCP packet", "from", conn.RemoteAddr(), "to", conn.LocalAddr())

			tcpAddr, err := net.ResolveTCPAddr("tcp", conn.LocalAddr().String())
			if err != nil {
				slog.Error("Failed to resolve TCP address:", "address", conn.LocalAddr(), "err", err)
				_ = conn.Close()
				return
			}

			fqdn, err := pool.RevResolve(tcpAddr.IP)
			if err != nil {
				slog.Error("Failed to resolve FQDN:", "err", err)
				_ = conn.Close()
				return
			}

			proxyConn, err := tcpDialer.Dial("tcp", fqdn+":"+strconv.Itoa(tcpAddr.Port))
			if err != nil {
				slog.Error("Failed to dial:", "err", err)
				_ = conn.Close()
				return
			}

			relay := func(src net.Conn, dst net.Conn) {
				_, _ = io.Copy(dst, src)
				_ = dst.Close()
				_ = src.Close()
			}
			go relay(conn, proxyConn)
			go relay(proxyConn, conn)

		case udpProtocolNumber:
			slog.Warn("Not implemented yet")
		default:
			slog.Error("Unexpected error: unknown protocol number:", "t", t)
		}
	})

	slog.Info("FIPPF started")

	termChan := make(chan os.Signal)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)

	<-termChan
	slog.Info("Quit")
}
