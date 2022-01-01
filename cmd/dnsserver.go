package cmd

import (
	"net"
	"net/url"
        "fmt"
        "time"

	"github.com/pterm/pterm"
	log "github.com/sirupsen/logrus"
)

func UDPServer(serverUrl string, serverTimeout int) {
	listenUrl, err := url.Parse("//" + serverUrl)
	if err != nil {
		pterm.Error.Println("Failed to parse server url")
		log.Fatal("Failed to parse server url")
	}

	// replace ip with 0.0.0.0:port
	listenUrl.Host = "0.0.0.0:" + listenUrl.Port()

	// listen to incoming udp packets
        listenPort := ":" + listenUrl.Port()

	pterm.Info.Println("Starting Fake DNS server on UDP port", listenUrl.Host)
        pterm.Warning.Printf("Make Sure that UDP port %s is available\n", listenUrl.Port())
	log.Info("Starting Fake DNS server on UDP Port", listenUrl.Host)
	pc, err := net.ListenPacket("udp", listenPort)
	if err != nil {
		log.Fatal(err)
	}
	defer pc.Close()
        timeout := time.Duration(serverTimeout) * time.Second
	for {
                buf := make([]byte, 1024)
                pc.SetDeadline(time.Now().Add(timeout))
                _, addr, err := pc.ReadFrom(buf)
                if err != nil {
                        return
                }
                go ReportVulnUDPIP(addr)
        }

}

func ReportVulnUDPIP(addr net.Addr) {
        vulnIP, _, _ := net.SplitHostPort(addr.String())
        msg := fmt.Sprintf("Reason:DNS, Remote addr: %s", vulnIP)
	log.Info(msg)
	pterm.Success.Println(msg)
}
