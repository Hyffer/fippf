package main

import (
	"reflect"
	"testing"
)

func Test_parseDNSFromNetworkctl(t *testing.T) {
	type args struct {
		output string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "Normal networkctl output 1",
			args: args{
				output: `
● 9: eth0
                     Link File: /usr/lib/systemd/network/99-default.link
                  Network File: /run/systemd/network/10-netplan-eth0.network
                          Type: ether
                         State: routable (configured)
                  Online state: online
                        Driver: veth
                    HW Address: 12:34:56:78:90:ab (Xensource, Inc.)
                           MTU: 1500 (min: 68, max: 65535)
                         QDisc: noqueue
  IPv6 Address Generation Mode: eui64
          Queue Length (Tx/Rx): 16/16
              Auto negotiation: no
                         Speed: 10Gbps
                        Duplex: full
                          Port: tp
                       Address: 10.34.64.111 (DHCP4 via 10.34.64.1)
                                fedc:ba09:8765:4321:1034:56ff:fe78:90ab
                                fe80::1034:56ff:fe78:90ab
                       Gateway: 10.34.64.1
                                fe80::fcdc:baff:fe65:4321
                           DNS: 10.34.64.1
                                fe80::fcdc:baff:fe65:4321
                Search Domains: incus
             Activation Policy: up
           Required For Online: yes
               DHCP4 Client ID: 12:34:56:78:90:ab
             DHCP6 Client IAID: 0x1234cdef
             DHCP6 Client DUID: DUID-EN/Vendor:1234567890abcdef1234567890ab
`,
			},
			want:    []string{"10.34.64.1", "fe80::fcdc:baff:fe65:4321"},
			wantErr: false,
		},

		{
			name: "Normal networkctl output 2",
			args: args{
				output: `
● 2: enp3s0                     
                     Link File: /usr/lib/systemd/network/99-default.link
                  Network File: /run/systemd/network/10-netplan-enp3s0.network
                          Type: ether
                         State: routable (configured)
                  Online state: online
                          Path: pci-0000:03:00.0
                        Driver: r8168
                        Vendor: Realtek Semiconductor Co., Ltd.
                         Model: RTL8111/8168/8411 PCI Express Gigabit Ethernet Controller (Onboard Ethernet)
                    HW Address: 12:34:56:78:90:ab (GIGA-BYTE TECHNOLOGY CO.,LTD.)
                           MTU: 1500 (min: 68, max: 9194)
                         QDisc: fq_codel
  IPv6 Address Generation Mode: eui64
          Queue Length (Tx/Rx): 1/1
              Auto negotiation: yes
                         Speed: 1Gbps
                        Duplex: full
                          Port: tp
                       Address: 192.168.1.100 (DHCP4 via 192.168.1.1)
                                1234:abc:5678:deff:1034:56ff:fe78:90ab
                                fe80::1034:56ff:fe78:90ab
                       Gateway: 192.168.1.1
                                fe80::fcdc:baff:fe65:4321
                           DNS: 111.11.1.1
                                2.22.222.222
                                1234:abc:7890::1
                                2345::6666
             Activation Policy: up
           Required For Online: yes
               DHCP4 Client ID: IAID:0x1234cdef/DUID
             DHCP6 Client IAID: 0x1234cdef
             DHCP6 Client DUID: DUID-EN/Vendor:1234567890abcdef1234567890ab

Mar 23 13:54:15 my-server systemd-networkd[1551]: enp3s0: DHCPv6 error: No message of desired type
Mar 23 13:57:46 my-server systemd-networkd[1551]: enp3s0: DHCPv6 error: No message of desired type
Mar 23 14:05:24 my-server systemd-networkd[1551]: enp3s0: DHCPv6 error: No message of desired type
Mar 23 14:09:53 my-server systemd-networkd[1551]: enp3s0: DHCPv6 error: No message of desired type
Mar 23 14:15:01 my-server systemd-networkd[1551]: enp3s0: DHCPv6 error: No message of desired type
Mar 23 14:24:21 my-server systemd-networkd[1551]: enp3s0: DHCPv6 error: No message of desired type
Mar 23 14:24:56 my-server systemd-networkd[1551]: enp3s0: DHCPv6 error: No message of desired type
Mar 23 14:24:59 my-server systemd-networkd[1551]: enp3s0: DHCPv6 error: No message of desired type
Mar 23 14:32:34 my-server systemd-networkd[1551]: enp3s0: DHCPv6 error: No message of desired type
Mar 23 14:36:58 my-server systemd-networkd[1551]: enp3s0: DHCPv6 error: No message of desired type
`,
			},
			want:    []string{"111.11.1.1", "2.22.222.222", "1234:abc:7890::1", "2345::6666"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDNSFromNetworkctl(tt.args.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDNSFromNetworkctl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseDNSFromNetworkctl() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseDNSFromNmcil(t *testing.T) {
	type args struct {
		output string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "Normal nmcil output 1",
			args: args{
				output: `
GENERAL.DEVICE:wlp3s0
GENERAL.TYPE:wifi
GENERAL.HWADDR:AB:CD:EF:12:34:56
GENERAL.MTU:1500
GENERAL.STATE:100 (connected)
GENERAL.CONNECTION:XXXX
GENERAL.CON-PATH:/org/freedesktop/NetworkManager/ActiveConnection/42
IP4.ADDRESS[1]:10.158.45.214/24
IP4.GATEWAY:10.158.45.254
IP4.ROUTE[1]:dst = 0.0.0.0/0, nh = 10.158.45.254, mt = 600
IP4.ROUTE[2]:dst = 10.158.45.0/24, nh = 0.0.0.0, mt = 600
IP4.DNS[1]:123.123.45.6
IP6.ADDRESS[1]:fe80::1234:5678:90ab:cdef/64
IP6.GATEWAY:
IP6.ROUTE[1]:dst = fe80::/64, nh = ::, mt = 1024
`,
			},
			want:    []string{"123.123.45.6"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDNSFromNmcil(tt.args.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDNSFromNmcil() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseDNSFromNmcil() got = %v, want %v", got, tt.want)
			}
		})
	}
}
