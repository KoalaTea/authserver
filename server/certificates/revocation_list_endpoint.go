package certificates

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/koalatea/authserver/server/ent/cert"
	authserverHttp "github.com/koalatea/authserver/server/http"
)

func (p *CertProvider) buildCrl(ctx context.Context) ([]byte, error) {
	revokedCerts := []pkix.RevokedCertificate{}
	certificatesQuery := p.graph.Cert.Query().Where(cert.Revoked(true))
	revokedCertsCount, err := certificatesQuery.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get the count of certificates: %+v", err)
	}
	revokedCertificates, err := certificatesQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get the certificates: %+v", err)
	}
	for _, revokedCertificate := range revokedCertificates {
		// Create a revoked certificate entry
		revokedCert := pkix.RevokedCertificate{
			SerialNumber:   big.NewInt(revokedCertificate.SerialNumber),
			RevocationTime: time.Now(),
		}
		revokedCerts = append(revokedCerts, revokedCert)
	}
	// Sign the updated CRL
	crlBytes, err := x509.CreateRevocationList(nil, &x509.RevocationList{
		SignatureAlgorithm:  p.ca.SignatureAlgorithm,
		Issuer:              p.ca.Subject,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(24 * time.Hour), // Example: next update in 24 hours
		RevokedCertificates: revokedCerts,
		Number:              big.NewInt(int64(revokedCertsCount)),
		Extensions:          []pkix.Extension{},
	}, p.ca, p.key)
	if err != nil {
		return nil, fmt.Errorf("failed to created the revocation list %+v", err)
	}
	// Write the updated CRL to a file (in PEM format)
	pemCRL := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})

	return pemCRL, nil
}

func (p *CertProvider) crlHandler(w http.ResponseWriter, r *http.Request) {
	// create the crl
	crlBytes, err := p.buildCrl(r.Context())
	if err != nil {
		http.Error(w, "Failed to read CRL file", http.StatusInternalServerError)
		log.Printf("Failed to read CRL file: %v", err) // Do better
	}

	// Set appropriate headers
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", "attachment; filename=crl.pem")

	// Write the CRL to the response
	w.Write(crlBytes)
}

func Endpoints(p *CertProvider) authserverHttp.RouteMap {
	routes := authserverHttp.RouteMap{}
	routes.HandleFunc("/certs/crl", p.crlHandler)
	return routes
}
