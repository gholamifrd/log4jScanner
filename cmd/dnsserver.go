package cmd

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

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
	log.Info("Starting Fake DNS server on UDP Port ", listenUrl.Host)
	pc, err := net.ListenPacket("udp", listenPort)
	if err != nil {
		pterm.Error.Println(err)
                os.Exit(1)
	}
	defer pc.Close()
        buf := make([]byte, 1024)
	for {
                n, addr, err := pc.ReadFrom(buf)
                if err != nil {
                        return
                }
                callback := string(buf[13:n])
                ReportVulnDNSIP(addr, callback)
        }
}

func ReportVulnDNSIP(addr net.Addr, callback string) {
        var traceIP string
        var tracePort string
        var traceParam string
        var traceService string
        vulnIP, _, _ := net.SplitHostPort(addr.String())

        traceList := strings.Split(callback, "_")
        if len(traceList) > 1 {
                traceIP = strings.Join(traceList[:4], ".")
                tracePort = traceList[4]
                if strings.Contains(callback, "VCenter") {
                        traceService = "(VCenter)"
                        traceParam = traceList[6]
                } else {
                        traceService = ""
                        traceParam = traceList[5]
                }
        } else {
                traceIP = vulnIP
                tracePort = "?"
                traceParam = "?"
                traceService = ""
        }
        msg := fmt.Sprintf("Vuln Service: %s:%s  Vuln Param: %s (DNS CallBack)%s", traceIP, tracePort, traceParam, traceService)
        log.Info(msg)
        if !DNSResultsMap[callback] {
                DNSResultsMap[callback] = true
                pterm.Success.Println(msg)
        }
}
