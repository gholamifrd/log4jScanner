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
	// succChan   chan string
        // hit     chan bool
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
	// LDAPServer.succChan = make(chan string, 10000)
	// LDAPServer.hit = make(chan bool)
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

	//pterm.Info.Println("Got LDAP search request: " + r.BaseObject())
	log.Info("Got LDAP search request: " + r.BaseObject())

	vulnerableLocationRaw := strings.Replace(string(r.BaseObject()), "_", ":", 1)
	vulnerableLocation := strings.Replace(string(vulnerableLocationRaw), "_", "/", 1)
        vulnerableIP := strings.Split(vulnerableLocation, "/")[0]
        vulnerableParameter := strings.Split(vulnerableLocation, "/")[1]

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)

	s.ReportIP(vulnerableIP, vulnerableParameter)

	return
}

func (s *Server) ReportIP(vulnerableServiceIP string, vulnerableServiceParameter string) {
	vulnUrl, err := url.Parse("//" + vulnerableServiceIP)
	if err != nil {
		pterm.Error.Println("Failed to parse vulnerable url: " + vulnerableServiceIP)
		log.Fatal("Failed to parse server url" + vulnerableServiceIP)
	}
        msg := fmt.Sprintf("Vulnerable IP: %s Vulnerable Paramete: %s (LDAP CallBack)", vulnerableServiceIP, vulnerableServiceParameter)
	log.Info(msg)
        if !LDAPResultsMap[msg] {
                pterm.Success.Println(msg)
                LDAPResultsMap[msg] = true
                // return
        }
        // pterm.Success.Println(msg)
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
