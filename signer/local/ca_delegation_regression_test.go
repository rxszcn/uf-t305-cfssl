package local

import (
	"reflect"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
)

// noCAProfile returns a signing policy that explicitly forbids issuing
// certificates with CA capability.
func noCAProfile() *config.Signing {
	return &config.Signing{
		Default: &config.SigningProfile{
			Usage:        []string{"digital signature", "key encipherment"},
			ExpiryString: "1h",
			Expiry:       1 * time.Hour,
			CAConstraint: config.CAConstraint{IsCA: false},
		},
	}
}

// TestSignCADelegationCSRRejectedByNoCAPolicy is the end-to-end group:
// a CSR whose extension list carries a CA-capability declaration
// (critical BasicConstraints with IsCA=true, here assembled together
// with the delegation extension) must be refused by a signing policy
// that forbids CA output, with a policy-violation error. Before the CSR
// extension-assembly fix, the delegation switch silently dropped the
// BasicConstraints extension from the CSR, so this same request was
// signed into a leaf certificate with no error.
func TestSignCADelegationCSRRejectedByNoCAPolicy(t *testing.T) {
	cr := &csr.CertificateRequest{
		CN:                "intermediate-gateway.example.com",
		CA:                &csr.CAConfig{PathLength: 0, PathLenZero: true},
		DelegationEnabled: true,
		KeyRequest:        csr.NewKeyRequest(),
	}
	csrPEM, _, err := csr.ParseRequest(cr)
	if err != nil {
		t.Fatalf("could not generate csr: %v", err)
	}

	s := newCustomSigner(t, testECDSACaFile, testECDSACaKeyFile)
	s.policy = noCAProfile()

	_, err = s.Sign(signer.SignRequest{Request: string(csrPEM)})
	want := cferr.New(cferr.PolicyError, cferr.InvalidRequest)
	if !reflect.DeepEqual(err, want) {
		t.Fatalf("expected policy violation %v, got %v", want, err)
	}
}

// TestSignDelegationOnlyCSRAllowedByNoCAPolicy is the end-to-end
// control: the same request shape without the CA declaration carries no
// CA-capability claim, so the no-CA policy must sign it into a leaf
// certificate.
func TestSignDelegationOnlyCSRAllowedByNoCAPolicy(t *testing.T) {
	cr := &csr.CertificateRequest{
		CN:                "device-gateway.example.com",
		DelegationEnabled: true,
		KeyRequest:        csr.NewKeyRequest(),
	}
	csrPEM, _, err := csr.ParseRequest(cr)
	if err != nil {
		t.Fatalf("could not generate csr: %v", err)
	}

	s := newCustomSigner(t, testECDSACaFile, testECDSACaKeyFile)
	s.policy = noCAProfile()

	certPEM, err := s.Sign(signer.SignRequest{Request: string(csrPEM)})
	if err != nil {
		t.Fatalf("delegation-only CSR should sign under a no-CA policy, got %v", err)
	}
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("could not parse signed certificate: %v", err)
	}
	if cert.IsCA {
		t.Fatal("no-CA policy signed a CA certificate")
	}
}
