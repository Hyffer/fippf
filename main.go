package main

import (
	"github.com/miekg/dns"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"log/slog"
	"net"
	"os"
	"os/signal"
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

	tunIf, err := NewTunIf(
		viper.GetString("if_name"), viper.GetUint32("mtu"),
		viper.GetString("ip_range"), viper.GetString("ip6_range"),
	)
	if err != nil {
		slog.Error("Failed to create TUN interface:", "err", err)
		os.Exit(1)
	}
	defer tunIf.Close()

	tunIf.SetConnHandler(func(t uint32, conn net.Conn) {
		slog.Debug("receive packet", "from", conn.RemoteAddr(), "to", conn.LocalAddr())
	})

	pool := NewIPPool(tunIf.cidr, tunIf.ip, tunIf.cidr6, tunIf.ip6)
	dnsSrv := &dns.Server{
		Addr:    ":55",
		Net:     "udp",
		Handler: pool,
		UDPSize: 65535,
	}
	defer func(dnsSrv *dns.Server) {
		_ = dnsSrv.Shutdown()
	}(dnsSrv)

	slog.Info("FIPPF started")

	go func() {
		err := dnsSrv.ListenAndServe()
		if err != nil {
			slog.Error("Failed to start DNS dnsSrv:", "err", err)
		}
	}()

	termChan := make(chan os.Signal)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)

	<-termChan
	slog.Info("Quit")
}
