package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

func main() {
	flag.Parse()
	addr := flag.Arg(0)

	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         addr,
	}

	config.VerifyPeerCertificate = func(certificates [][]byte, _ [][]*x509.Certificate) error {
		certs := make([]*x509.Certificate, len(certificates))
		for i, asn1Data := range certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return errors.New("tls: failed to parse certificate from server: " + err.Error())
			}
			certs[i] = cert
		}

		opts := x509.VerifyOptions{
			Roots:         config.RootCAs,
			DNSName:       config.ServerName,
			Intermediates: x509.NewCertPool(),
		}

		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		if _, err := certs[0].Verify(opts); err != nil {
			return err
		}

		err := processCertificates(certs)

		return err
	}

	ips, err := net.LookupHost(addr)
	if err != nil {
		log.Fatal("\u001b[31m/!\\\u001b[0m Failed to resolve lookup: ", err.Error(), " \u001b[31m/!\\\u001b[0m")
	}
	fmt.Printf("\n\u001b[1m%v\u001b[0m resolves to:\n%v\n\n", addr, strings.Join(ips, ", "))

	conn, err := tls.Dial("tcp", addr+":443", config)
	if err != nil {
		log.Fatal("\u001b[31m/!\\\u001b[0m Failed: ", err.Error(), " \u001b[31m/!\\\u001b[0m")
	}
	log.Println("\u001b[32mSSL certificate verification successful\u001b[0m")
	conn.Close()
}

func processCertificates(certs []*x509.Certificate) error {
	fmt.Println("\u001b[1mTLS Certificate\u001b[0m")
	fmt.Printf(`Common Name: 			%v
Subject Alternative Names:	%v
Issuer:				%v
Serial Number:			%v
Signature algorithm:		%v

`, certs[0].Subject.CommonName, strings.Join(certs[0].DNSNames, ", "),
		certs[0].Issuer.CommonName, certs[0].SerialNumber, certs[0].SignatureAlgorithm)

	if isCertificateRevokedByOCSP(certs[0].Subject.CommonName, certs[0], certs[len(certs)-1], certs[0].OCSPServer) {
		return errors.New("tls: certificate has been revoked")
	}
	fmt.Println("TLS Certificate has not been revoked")

	fmt.Println("\n\u001b[1mCertificate chain\u001b[0m")

	for _, c := range certs {
		fmt.Printf(`Subject: %v
Valid from %v to %v
Issuer: %v

`, c.Subject.CommonName, c.NotBefore.Format(time.RFC822)[0:9], c.NotAfter.Format(time.RFC822)[0:9], c.Issuer.CommonName)
	}
	return nil
}

func isCertificateRevokedByOCSP(commonName string, cert, issuerCert *x509.Certificate, OCSPServer []string) bool {
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	buffer, err := ocsp.CreateRequest(cert, issuerCert, opts)
	if err != nil {
		return false
	}
	httpRequest, err := http.NewRequest(http.MethodPost, OCSPServer[0], bytes.NewBuffer(buffer))
	if err != nil {
		return false
	}
	ocspURL, err := url.Parse(OCSPServer[0])
	if err != nil {
		return false
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspURL.Host)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return false
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return false
	}

	ocspResponse, err := ocsp.ParseResponse(output, issuerCert)
	if err != nil {
		return false
	}
	if ocspResponse.Status == ocsp.Revoked {
		return true
	}
	return false
}
