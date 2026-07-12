package vault

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// parseImport decodes a PFX (PKCS#12, base64) or PEM bundle into the stored
// representation. Returns base64(DER cert), base64(PKCS#8 key), thumbprint,
// notBefore/notAfter, and the key type.
func parseImport(value, password string) (cerDER, privDER, thumb string, nbf, exp int64, kty string, err error) {
	// PEM: value is the PEM text (possibly base64-wrapped by the caller).
	if raw := maybeBase64(value); looksPEM(raw) {
		return parsePEM(raw)
	}
	// Otherwise treat as base64 PKCS#12.
	der, decErr := base64.StdEncoding.DecodeString(value)
	if decErr != nil {
		return "", "", "", 0, 0, "", fmt.Errorf("value is neither PEM nor base64 PKCS#12")
	}
	key, cert, decErr := pkcs12.Decode(der, password)
	if decErr != nil {
		return "", "", "", 0, 0, "", fmt.Errorf("PKCS#12 decode: %w", decErr)
	}
	return finish(cert, key)
}

func maybeBase64(v string) []byte {
	if looksPEM([]byte(v)) {
		return []byte(v)
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil {
		return b
	}
	return []byte(v)
}

func looksPEM(b []byte) bool {
	return len(b) > 10 && string(b[:10]) == "-----BEGIN"
}

func parsePEM(raw []byte) (cerDER, privDER, thumb string, nbf, exp int64, kty string, err error) {
	var cert *x509.Certificate
	var key any
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			if cert == nil {
				cert, err = x509.ParseCertificate(block.Bytes)
				if err != nil {
					return "", "", "", 0, 0, "", err
				}
			}
		case "PRIVATE KEY":
			key, _ = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, _ = x509.ParseECPrivateKey(block.Bytes)
		}
	}
	if cert == nil {
		return "", "", "", 0, 0, "", fmt.Errorf("no CERTIFICATE block in PEM")
	}
	return finish(cert, key)
}

func finish(cert *x509.Certificate, key any) (cerDER, privDER, thumb string, nbf, exp int64, kty string, err error) {
	sum := sha1.Sum(cert.Raw)
	cerDER = base64.StdEncoding.EncodeToString(cert.Raw)
	thumb = base64.RawURLEncoding.EncodeToString(sum[:])
	nbf, exp = cert.NotBefore.Unix(), cert.NotAfter.Unix()
	if key != nil {
		der, mErr := x509.MarshalPKCS8PrivateKey(key)
		if mErr != nil {
			return "", "", "", 0, 0, "", mErr
		}
		privDER = base64.StdEncoding.EncodeToString(der)
	}
	switch key.(type) {
	case *rsa.PrivateKey:
		kty = "RSA"
	case *ecdsa.PrivateKey:
		kty = "EC"
	default:
		kty = "RSA"
	}
	return cerDER, privDER, thumb, nbf, exp, kty, nil
}
