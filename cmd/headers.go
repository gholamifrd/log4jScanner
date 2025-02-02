package cmd

import (
        "net/http"
        "fmt"
        "strings"
)

var commonHeaders = []string{
    // "Accept-Charset",
    // "Accept-Datetime",
    // "Accept-Encoding",
    // "Accept-Language",
    // "Cache-Control",
    // "Cookie",
    // "DNT",
    "Forwarded",
    "Forwarded-For",
    "Forwarded-For-Ip",
    "Forwarded-Proto",
    "From",
    // "Max-Forwards",
    // "Origin",
    // "Pragma",
    // "Referer",
    // "TE",
    // "True-Client-IP",
    // "Upgrade",
    // "Via",
    // "Warning",
    "X-ATT-DeviceId",
    "X-Api-Version",
    "X-Att-Deviceid",
    "X-CSRFToken",
    "X-Correlation-ID",
    "X-Csrf-Token",
    "X-Do-Not-Track",
    "X-Foo",
    "X-Foo-Bar",
    "X-Forward-For",
    "X-Forward-Proto",
    "X-Forwarded",
    "X-Forwarded-By",
    "X-Forwarded-For",
    "X-Forwarded-For-Original",
    "X-Forwarded-Host",
    "X-Forwarded-Port",
    "X-Forwarded-Proto",
    "X-Forwarded-Protocol",
    "X-Forwarded-Scheme",
    "X-Forwarded-Server",
    "X-Forwarded-Ssl",
    "X-Forwarder-For",
    "X-Frame-Options",
    "X-From",
    "X-Geoip-Country",
    "X-HTTP-Method-Override",
    "X-Http-Destinationurl",
    "X-Http-Host-Override",
    "X-Http-Method",
    "X-Http-Method-Override",
    "X-Http-Path-Override",
    "X-Https",
    "X-Htx-Agent",
    "X-Hub-Signature",
    "X-If-Unmodified-Since",
    "X-Imbo-Test-Config",
    "X-Insight",
    "X-Ip",
    "X-Ip-Trail",
    "X-ProxyUser-Ip",
    "X-Request-ID",
    "X-Requested-With",
    "X-UIDH",
    "X-Wap-Profile",
    "X-XSRF-TOKEN",
}

func addCommonHeaders(headers *http.Header, headerValue string) {
        for _, header := range commonHeaders {
                headers.Add(header,fmt.Sprintf("%s_%s}", strings.TrimSuffix(headerValue, "}"), header))
        }
}
