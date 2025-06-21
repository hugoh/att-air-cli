package gateway

import (
	"net/http"
	"net/http/httputil"

	"github.com/sirupsen/logrus"
)

type DebugTransport struct {
	Transport http.RoundTripper
}

func (d *DebugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport := d.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	logrus.WithFields(logrus.Fields{
		"method": req.Method,
		"url":    req.URL.String(),
	}).Debug("HTTP request")

	if logrus.IsLevelEnabled(logrus.TraceLevel) {
		dumpReq, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			logrus.WithError(err).Trace("could not dump HTTP request")
		} else {
			logrus.Tracef("HTTP Request:\n%s", dumpReq)
		}
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		logrus.WithError(err).Trace("HTTP request failed")
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"code": resp.StatusCode,
	}).Debug("HTTP response")

	if logrus.IsLevelEnabled(logrus.TraceLevel) {
		dumpResp, err := httputil.DumpResponse(resp, true)
		if err != nil {
			logrus.WithError(err).Trace("could not dump HTTP response")
		} else {
			logrus.Tracef("HTTP Response:\n%s", dumpResp)
		}
	}

	return resp, nil
}

func debugHttpClient(client HTTPClientInterface) {
	transport := client.Transport()
	client.SetTransport(&DebugTransport{Transport: transport})
}
