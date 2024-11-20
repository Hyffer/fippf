package main

import (
	"errors"
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
		viper.GetString("if_name"), viper.GetInt("mtu"),
		viper.GetString("ip_range"), viper.GetString("ip6_range"),
	)
	if err != nil {
		slog.Error("Failed to create TUN interface:", "err", err)
		os.Exit(1)
	}
	defer tunIf.Close()

	slog.Info("FIPPF started")

	// receive packets
	go func() {
		buf := make([][]byte, 1)
		buf[0] = make([]byte, tunIf.mtu)
		size := make([]int, 1)
		for {
			_, err := tunIf.Read(buf, size, 0)
			if err != nil {
				switch {
				case errors.Is(err, os.ErrClosed):
					break
				default:
					slog.Error("Failed to read packet from TUN interface:", "err", err)
				}
			} else {
				// ipv4
				if buf[0][0]>>4 == 4 {
					slog.Debug("IPv4 Packet:", "from", net.IP(buf[0][12:16]), "to", net.IP(buf[0][16:20]))
				}
				// ipv6
				if buf[0][0]>>4 == 6 {
					slog.Debug("IPv6 Packet:", "from", net.IP(buf[0][8:24]), "to", net.IP(buf[0][24:40]))
				}
			}
		}
	}()

	termChan := make(chan os.Signal)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)

	<-termChan
	slog.Info("Quit")
}
