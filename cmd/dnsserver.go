package cmd

import (
	"net"
	"net/url"
        "fmt"
        // "time"
        "os"

	"github.com/pterm/pterm"
	log "github.com/sirupsen/logrus"
)

var DNSResultsMap = make(map[string]bool)

func StartDNSServer(serverUrlDNS string, serverTimeout int) {
	listenUrl, err := url.Parse("//" + serverUrlDNS)
	if err != nil {
		pterm.Error.Println("Failed to parse server url")
		log.Fatal("Failed to parse server url")
	}

	// replace ip with 0.0.0.0:port
	listenUrl.Host = "0.0.0.0:" + listenUrl.Port()

	// listen to incoming udp packets
        listenPort := ":" + listenUrl.Port()

	pterm.Info.Println("Starting Fake DNS server on UDP port ", listenUrl.Host)
        pterm.Warning.Printf("Make Sure that UDP port %s is available\n", listenUrl.Port())
        fmt.Println()
	log.Info("Starting Fake DNS server on UDP Port", listenUrl.Host)
	pc, err := net.ListenPacket("udp", listenPort)
	if err != nil {
		pterm.Error.Println(err)
                os.Exit(1)
	}
	defer pc.Close()
        // timeout := time.Duration(serverTimeout) * time.Second
	for {
                buf := make([]byte, 1024)
                // pc.SetDeadline(time.Now().Add(timeout))
                _, addr, err := pc.ReadFrom(buf)
                if err != nil {
                        return
                }
                go ReportVulnDNSIP(addr)
        }
}

func ReportVulnDNSIP(addr net.Addr) {
        vulnIP, _, _ := net.SplitHostPort(addr.String())
        msg := fmt.Sprintf("Vulnerable IP: %s  (DNS CallBack)", vulnIP)
        log.Info(msg)
        if DNSResultsMap[msg] {
                return
        }
        DNSResultsMap[msg] = true
        pterm.Success.Println(msg)
}
