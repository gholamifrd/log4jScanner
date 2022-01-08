package cmd

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	ldap "github.com/vjeantet/ldapserver"

	"github.com/pterm/pterm"
	log "github.com/sirupsen/logrus"
)

var LDAPServer *Server
var LDAPResultsMap = make(map[string]bool)

type Server struct {
	server  *ldap.Server
	sChan   chan string
	timeout time.Duration
}

func StartLDAPServer(ctx context.Context, serverUrl string, serverTimeout int) {
	pterm.Info.Println("Server URL: " + serverUrl)
	log.Info("Server URL: " + serverUrl)
	listenUrl, err := url.Parse("//" + serverUrl)
	if err != nil {
		pterm.Error.Println("Failed to parse server url")
		log.Fatal("Failed to parse server url")
	}
	// replace ip with 0.0.0.0:port
	listenUrl.Host = "0.0.0.0:" + listenUrl.Port()

	pterm.Info.Println("Starting internal LDAP server on", listenUrl.Host)
        pterm.Warning.Printf("Make Sure that TCP port %s is available\n", listenUrl.Port())
	log.Info("Starting LDAP server on ", listenUrl.Host)
	LDAPServer = NewServer()
	LDAPServer.sChan = make(chan string, 10000)
	LDAPServer.timeout = time.Duration(serverTimeout) * time.Second

	go LDAPServer.server.ListenAndServe(listenUrl.Host)
}

func NewServer() *Server {
	s := &Server{
		server: ldap.NewServer(),
	}

	ldap.Logger = log.StandardLogger()

	routes := ldap.NewRouteMux()
	routes.Bind(s.handleBind)
	routes.Search(s.handleSearch)

	s.server.Handle(routes)

	return s
}

func (s *Server) handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	w.Write(res)
	return
}

func (s *Server) handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	log.Info("Got LDAP search request: " + r.BaseObject())

        callback := string(r.BaseObject())
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)

	s.ReportIP(callback)

	return
}

func (s *Server) ReportIP(callback string) {
        var traceIP string
        var tracePort string
        var traceParam string
        var traceService string
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
                traceIP = "?"
                tracePort = "?"
                traceParam = "?"
                traceService = ""
        }

        vulnerableService:= fmt.Sprintf("//%s:%s", traceIP, tracePort)
        vulnUrl, err := url.Parse(vulnerableService)
	if err != nil {
		pterm.Error.Println("Failed to parse vulnerable url: " + vulnerableService)
		log.Fatal("Failed to parse server url" + vulnerableService)
	}
        msg := fmt.Sprintf("Vuln Service: %s:%s  Vuln Param: %s (LDAP CallBack)%s", traceIP, tracePort, traceParam, traceService)
	log.Info(msg)
        if contains(targetIPs, traceIP) {
                if !LDAPResultsMap[callback] {
                        LDAPResultsMap[callback] = true
                        pterm.Success.Prefix = pterm.Prefix{
                        Text:  "VULNERABLE",
                        Style: pterm.NewStyle(pterm.BgRed, pterm.FgBlack),
                        }
                        pterm.Success.Println(msg)
                }
        }
	if s != nil && s.sChan != nil {
		resMsg := fmt.Sprintf("vulnerable,%s,%s,", vulnUrl.Hostname(), vulnUrl.Port())
		updateCsvRecords(resMsg)
		s.sChan <- resMsg
	}
}

func (s *Server) Stop() {
	spinnerSuccess, _ := pterm.DefaultSpinner.Start("Stopping LDAP server")
	timeout := LDAPServer.timeout
	time.Sleep(timeout)
	s.server.Stop()
	err := spinnerSuccess.Stop()
	if err != nil {
		log.Fatal(err)
	}
}
