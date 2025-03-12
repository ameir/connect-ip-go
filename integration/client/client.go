package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/connect-ip-go/integration/internal/utils"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"
)

const (
	proxyPort   = 443
	PROXY_ADDR  = "194.166.0.2"
	SERVER_ADDR = "194.166.100.3"
)

func main() {

	proxyAddr := netip.AddrPortFrom(netip.MustParseAddr(PROXY_ADDR), uint16(proxyPort))

	keyLog, err := os.Create("keys.txt")
	if err != nil {
		log.Fatalf("failed to create key log file: %v", err)
	}
	defer keyLog.Close()
	dev, ipconn, err := establishConn(proxyAddr, keyLog)
	if err != nil {
		log.Fatalf("failed to establish connection to %s: %v", err, proxyAddr)
	}
	log.Println("created tun interface", dev.Name())

	proxy(ipconn, dev)
}

func establishConn(proxyAddr netip.AddrPort, keyLog io.Writer) (*water.Interface, *connectip.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0)})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}

	conn, err := quic.Dial(
		ctx,
		udpConn,
		&net.UDPAddr{IP: proxyAddr.Addr().AsSlice(), Port: int(proxyAddr.Port())},
		&tls.Config{
			ServerName:         "proxy",
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
			KeyLogWriter:       keyLog,
		},
		&quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
			KeepAlivePeriod:   30 * time.Second,
			MaxIdleTimeout:    time.Hour,
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial QUIC connection: %w", err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	hconn := tr.NewClientConn(conn)

	template := uritemplate.MustNew(fmt.Sprintf("https://proxy:%d/vpn", proxyAddr.Port()))
	ipconn, rsp, err := connectip.Dial(ctx, hconn, template)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial connect-ip connection: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
	}
	log.Printf("connected to VPN server: %s", proxyAddr)

	routes, err := ipconn.Routes(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get routes: %w", err)
	}
	localPrefixes, err := ipconn.LocalPrefixes(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get local prefixes: %w", err)
	}

	dev, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create TUN device: %w", err)
	}
	log.Printf("created TUN device: %s", dev.Name())

	link, err := netlink.LinkByName(dev.Name())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TUN interface: %w", err)
	}
	for _, p := range localPrefixes {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: utils.PrefixToIPNet(p)}); err != nil {
			return nil, nil, fmt.Errorf("failed to add address assigned by peer %s: %w", p, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
	}

	for _, route := range routes {
		log.Printf("adding routes for %s - %s (protocol: %d)", route.StartIP, route.EndIP, route.IPProtocol)
		for _, prefix := range route.Prefixes() {
			r := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       utils.PrefixToIPNet(prefix),
			}
			if err := netlink.RouteReplace(r); err != nil {
				return nil, nil, fmt.Errorf("failed to add route: %w", err)
			}
		}
	}
	return dev, ipconn, nil
}

func proxy(ipconn *connectip.Conn, dev *water.Interface) error {
	defer closeDev(dev)
	defer ipconn.Close()

	errChan := make(chan error, 2)
	go func() {
		for {
			b := make([]byte, 1500)
			n, err := ipconn.ReadPacket(b)
			if err != nil {
				fmt.Printf("failed to read from connection: %s", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if _, err := dev.Write(b[:n]); err != nil {
				errChan <- fmt.Errorf("failed to write to TUN: %w", err)
				return
			}
		}
	}()

	go func() {
		for {
			b := make([]byte, 1500)
			n, err := dev.Read(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from TUN: %w", err)
				return
			}
			icmp, err := ipconn.WritePacket(b[:n])
			if err != nil {
				fmt.Printf("failed to write to connection: %s", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if len(icmp) > 0 {
				log.Printf("sending ICMP packet on %s", dev.Name())
				if _, err := dev.Write(icmp); err != nil {
					log.Printf("failed to write ICMP packet: %v", err)
				}
			}
		}
	}()

	err := <-errChan
	log.Printf("error proxying: %v", err)
	<-errChan // wait for the other goroutine to finish
	return err
}

func ipForURL(addr netip.Addr) string {
	if addr.Is4() {
		return addr.String()
	}
	return fmt.Sprintf("[%s]", addr)
}

func closeDev(dev *water.Interface) {
	if dev != nil {
		dev.Close()
	}
}
