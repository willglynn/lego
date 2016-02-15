package ocsp

import (
	"bytes"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

const (
	// OCSPGood means that the certificate is valid.
	OCSPGood = ocsp.Good
	// OCSPRevoked means that the certificate has been deliberately revoked.
	OCSPRevoked = ocsp.Revoked
	// OCSPUnknown means that the OCSP responder doesn't know about the certificate.
	OCSPUnknown = ocsp.Unknown
	// OCSPServerFailed means that the OCSP responder failed to process the request.
	OCSPServerFailed = ocsp.ServerFailed
)

// GetOCSPForCert takes a PEM encoded cert or cert bundle returning the raw OCSP response,
// the parsed response, and an error, if any. The returned []byte can be passed directly
// into the OCSPStaple property of a tls.Certificate. If the bundle only contains the
// issued certificate, this function will try to get the issuer certificate from the
// IssuingCertificateURL in the certificate. If the []byte and/or ocsp.Response return
// values are nil, the OCSP status may be assumed OCSPUnknown.
func GetOCSPForCert(bundle []byte) ([]byte, *ocsp.Response, error) {
	certificates, err := parsePEMBundle(bundle)
	if err != nil {
		return nil, nil, err
	}

	// We expect the certificate slice to be ordered downwards the chain.
	// SRV CRT -> CA. We need to pull the leaf and issuer certs out of it,
	// which should always be the first two certificates. If there's no
	// OCSP server listed in the leaf cert, there's nothing to do. And if
	// we have only one certificate so far, we need to get the issuer cert.
	issuedCert := certificates[0]
	if len(issuedCert.OCSPServer) == 0 {
		return nil, nil, errors.New("no OCSP server specified in cert")
	}
	if len(certificates) == 1 {
		// TODO: build fallback. If this fails, check the remaining array entries.
		if len(issuedCert.IssuingCertificateURL) == 0 {
			return nil, nil, errors.New("no issuing certificate URL")
		}

		resp, err := httpGet(issuedCert.IssuingCertificateURL[0])
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()

		issuerBytes, err := ioutil.ReadAll(http.MaxBytesReader(nil, resp.Body, 1024*1024))
		if err != nil {
			return nil, nil, err
		}

		issuerCert, err := x509.ParseCertificate(issuerBytes)
		if err != nil {
			return nil, nil, err
		}

		// Insert it into the slice on position 0
		// We want it ordered right SRV CRT -> CA
		certificates = append(certificates, issuerCert)
	}
	issuerCert := certificates[1]

	// Finally kick off the OCSP request.
	ocspReq, err := ocsp.CreateRequest(issuedCert, issuerCert, nil)
	if err != nil {
		return nil, nil, err
	}

	reader := bytes.NewReader(ocspReq)
	req, err := httpPost(issuedCert.OCSPServer[0], "application/ocsp-request", reader)
	if err != nil {
		return nil, nil, err
	}
	defer req.Body.Close()

	ocspResBytes, err := ioutil.ReadAll(http.MaxBytesReader(nil, req.Body, 1024*1024))
	ocspRes, err := ocsp.ParseResponse(ocspResBytes, issuerCert)
	if err != nil {
		return nil, nil, err
	}

	if ocspRes.Certificate == nil {
		err = ocspRes.CheckSignatureFrom(issuerCert)
		if err != nil {
			return nil, nil, err
		}
	}

	return ocspResBytes, ocspRes, nil
}
