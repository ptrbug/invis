package main

import (
	"crypto/tls"
	"sync"
	"time"

	faketls "github.com/ptrbug/invis/tls"
)

type webCert struct {
	webAddr      string
	mutex        sync.Mutex
	certNotAfter time.Time
	cert         *faketls.Certificate
}

func (p *webCert) updateWebCert() (version uint16, err error) {
	cert, certNotAfter, version, err := getTLSCert(p.webAddr)
	if err != nil {
		return version, err
	}

	p.mutex.Lock()
	update := false
	if cert != nil {
		if p.cert == nil || certNotAfter.After(p.certNotAfter) {
			update = true
		}
	}
	if update {
		p.cert = cert
		p.certNotAfter = certNotAfter
	}
	p.mutex.Unlock()

	return version, nil
}

func (p *webCert) getCert() *faketls.Certificate {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.cert
}

func (p *webCert) checkUpdateOnTimer() {
	for {
		select {
		case <-time.After(time.Hour * 24):
			p.updateWebCert()
		}
	}
}

func getTLSCert(webAddr string) (cert *faketls.Certificate, certNotAfter time.Time, version uint16, err error) {

	config := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", webAddr, config)
	if err != nil {
		return cert, certNotAfter, version, err
	}
	state := conn.ConnectionState()
	conn.Close()

	var certsFromWeb [][]byte
	for _, cert := range state.PeerCertificates {
		certsFromWeb = append(certsFromWeb, cert.Raw)
	}
	cert = &faketls.Certificate{
		Certificate:                 certsFromWeb,
		OCSPStaple:                  state.OCSPResponse,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
	}

	if len(state.PeerCertificates) > 0 {
		certNotAfter = state.PeerCertificates[0].NotAfter
	}
	version = state.Version

	return cert, certNotAfter, version, err
}
