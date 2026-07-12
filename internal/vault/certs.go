package vault

// Certificates: self-signed issuance (issuer "Self") and PFX/PEM import.
// Real CA integration is a non-goal. Creating a certificate also
// materializes the linked key (/keys) and secret (/secrets) under the same
// name, exactly as real Key Vault does.

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/store"
)

// certPolicy is the subset of the certificate policy the emulator honors.
type certPolicy struct {
	KeyProps *struct {
		Kty     string `json:"kty"`
		KeySize int    `json:"key_size"`
		Crv     string `json:"crv"`
	} `json:"key_props"`
	X509Props *struct {
		Subject string `json:"subject"`
		SANs    *struct {
			DNSNames []string `json:"dns_names"`
		} `json:"sans"`
		ValidityMonths int `json:"validity_months"`
	} `json:"x509_props"`
	IssuerRef *struct {
		Name string `json:"name"`
	} `json:"issuer"`
}

func parsePolicy(raw json.RawMessage) certPolicy {
	var p certPolicy
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &p)
	}
	return p
}

// issueSelfSigned mints a self-signed cert from a policy, returning
// base64(DER cert), base64(PKCS#8 key), thumbprint (base64url SHA-1), and the
// notBefore/notAfter.
func issueSelfSigned(p certPolicy, now int64) (cerDER, privDER, thumb string, nbf, exp int64, err error) {
	kty, keySize, crv := "RSA", 2048, ""
	if p.KeyProps != nil {
		if p.KeyProps.Kty != "" {
			kty = p.KeyProps.Kty
		}
		keySize, crv = p.KeyProps.KeySize, p.KeyProps.Crv
	}
	privB64, _, err := generateKey(kty, keySize, crv)
	if err != nil {
		return "", "", "", 0, 0, err
	}
	priv, err := parseKey(privB64)
	if err != nil {
		return "", "", "", 0, 0, err
	}

	subject := "CN=emulator"
	months := 12
	var dnsNames []string
	if p.X509Props != nil {
		if p.X509Props.Subject != "" {
			subject = p.X509Props.Subject
		}
		if p.X509Props.ValidityMonths > 0 {
			months = p.X509Props.ValidityMonths
		}
		if p.X509Props.SANs != nil {
			dnsNames = p.X509Props.SANs.DNSNames
		}
	}
	cn := subject
	if len(subject) > 3 && subject[:3] == "CN=" {
		cn = subject[3:]
	}
	notBefore := time.Unix(now, 0).UTC()
	notAfter := notBefore.AddDate(0, months, 0)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", 0, 0, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, publicOf(priv), priv)
	if err != nil {
		return "", "", "", 0, 0, err
	}
	sum := sha1.Sum(der)
	return base64.StdEncoding.EncodeToString(der), privB64,
		base64.RawURLEncoding.EncodeToString(sum[:]), notBefore.Unix(), notAfter.Unix(), nil
}

// generateCSR mints a key from the policy and a PKCS#10 CSR over it — the
// artifact an external issuer signs. Returns base64(PKCS#8) key, base64(DER)
// CSR, and the normalized kty.
func generateCSR(p certPolicy) (privDER, csrDER, kty string, err error) {
	kty, keySize, crv := "RSA", 2048, ""
	if p.KeyProps != nil {
		if p.KeyProps.Kty != "" {
			kty = p.KeyProps.Kty
		}
		keySize, crv = p.KeyProps.KeySize, p.KeyProps.Crv
	}
	privB64, _, err := generateKey(kty, keySize, crv)
	if err != nil {
		return "", "", "", err
	}
	priv, err := parseKey(privB64)
	if err != nil {
		return "", "", "", err
	}
	subject, dnsNames := "CN=emulator", []string(nil)
	if p.X509Props != nil {
		if p.X509Props.Subject != "" {
			subject = p.X509Props.Subject
		}
		if p.X509Props.SANs != nil {
			dnsNames = p.X509Props.SANs.DNSNames
		}
	}
	cn := subject
	if len(subject) > 3 && subject[:3] == "CN=" {
		cn = subject[3:]
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dnsNames}, priv)
	if err != nil {
		return "", "", "", err
	}
	return privB64, base64.StdEncoding.EncodeToString(der), normalizeKty(kty), nil
}

func publicOf(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	}
	return nil
}

// materialize stores the cert's linked key (public JWK backed by the private
// key) and secret (base64 PFX-equivalent: here the PKCS#8 key + cert PEM
// bundle, opaque to callers) under the same name — as real Key Vault does.
func (s *Service) materialize(vault, name string, cv *store.CertVersion, kty string) error {
	if err := s.Store.SetKey(&store.KeyVersion{
		Vault: vault, Name: name, Kty: kty, PrivateDER: cv.PrivateDER, Enabled: true, Version: cv.Version,
	}); err != nil {
		return err
	}
	bundle, _ := json.Marshal(map[string]string{"key": cv.PrivateDER, "cer": cv.CerDER})
	return s.Store.SetSecret(&store.SecretVersion{
		Vault: vault, Name: name, Value: base64.StdEncoding.EncodeToString(bundle),
		ContentType: "application/x-pkcs12", Enabled: true, Version: cv.Version,
	})
}

func (s *Service) certAttrs(v *store.CertVersion) attributes {
	return attributes{
		Enabled: &v.Enabled, NBF: v.NBF, Exp: v.Exp,
		Created: v.CreatedAt, Updated: v.UpdatedAt,
		RecoveryLevel: "Recoverable+Purgeable", RecoverableDays: s.Cfg.SoftDeleteRetentionDays,
	}
}

// certBundle is the GET /certificates/{name} shape.
func (s *Service) certBundle(r *http.Request, v *store.CertVersion) map[string]any {
	der, _ := base64.StdEncoding.DecodeString(v.CerDER)
	tags := map[string]string{}
	_ = json.Unmarshal([]byte(v.TagsJSON), &tags)
	return map[string]any{
		"id":         fmt.Sprintf("%s/certificates/%s/%s", s.baseURL(r), v.Name, v.Version),
		"kid":        fmt.Sprintf("%s/keys/%s/%s", s.baseURL(r), v.Name, v.Version),
		"sid":        fmt.Sprintf("%s/secrets/%s/%s", s.baseURL(r), v.Name, v.Version),
		"cer":        der,
		"x5t":        v.Thumbprint,
		"attributes": s.certAttrs(v),
		"policy":     json.RawMessage(v.PolicyJSON),
		"tags":       tags,
	}
}

func certNotFound(w http.ResponseWriter, name string) {
	writeKVErr(w, http.StatusNotFound, "CertificateNotFound",
		fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
}

// createCertificate is POST /certificates/{name}/create. Issuance is
// synchronous (self-signed), so the operation is returned already completed —
// the SDK polls /pending once and proceeds.
func (s *Service) createCertificate(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	var body struct {
		Policy     json.RawMessage   `json:"policy"`
		Attributes *attributes       `json:"attributes"`
		Tags       map[string]string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "Malformed JSON body.")
		return
	}
	pol := parsePolicy(body.Policy)
	// A named (non-Self) issuer starts an asynchronous operation: the emulator
	// generates the key + a PKCS#10 CSR and waits for an external signer to
	// return the certificate via MergeCertificate. "Self" (or unset) issues a
	// self-signed certificate synchronously.
	if pol.IssuerRef != nil && pol.IssuerRef.Name != "" && pol.IssuerRef.Name != "Self" {
		s.createPendingCertificate(w, r, vault, name, pol, body.Policy)
		return
	}
	cerDER, privDER, thumb, nbf, exp, err := issueSelfSigned(pol, s.Store.Now())
	if err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", err.Error())
		return
	}
	kty := "RSA"
	if pol.KeyProps != nil && pol.KeyProps.Kty != "" {
		kty = normalizeKty(pol.KeyProps.Kty)
	}
	cv := &store.CertVersion{
		Vault: vault, Name: name, CerDER: cerDER, PrivateDER: privDER, Thumbprint: thumb,
		Enabled: true, NBF: &nbf, Exp: &exp,
	}
	if len(body.Policy) > 0 {
		cv.PolicyJSON = string(body.Policy)
	}
	if body.Tags != nil {
		raw, _ := json.Marshal(body.Tags)
		cv.TagsJSON = string(raw)
	}
	if err := s.Store.SetCert(cv); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeKVErr(w, http.StatusConflict, "Conflict",
				"Certificate is in a deleted but recoverable state; recover or purge it first.")
			return
		}
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if err := s.materialize(vault, name, cv, kty); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, s.certOperation(r, name, "completed"))
}

// certOperation is the CertificateOperation shape the SDK polls.
func (s *Service) certOperation(r *http.Request, name, status string) map[string]any {
	return map[string]any{
		"id":         fmt.Sprintf("%s/certificates/%s/pending", s.baseURL(r), name),
		"status":     status,
		"target":     fmt.Sprintf("%s/certificates/%s", s.baseURL(r), name),
		"issuer":     map[string]string{"name": "Self"},
		"request_id": store.NewVersionID(),
	}
}

// pendingOperation is the CertificateOperation for an in-progress (external
// issuer) request: status "inProgress" and the CSR the caller must sign.
func (s *Service) pendingOperation(r *http.Request, p *store.PendingCert) map[string]any {
	csr, _ := base64.StdEncoding.DecodeString(p.CSRDER)
	return map[string]any{
		"id":         fmt.Sprintf("%s/certificates/%s/pending", s.baseURL(r), p.Name),
		"status":     "inProgress",
		"target":     fmt.Sprintf("%s/certificates/%s", s.baseURL(r), p.Name),
		"issuer":     map[string]string{"name": p.Issuer},
		"csr":        csr,
		"request_id": store.NewVersionID(),
	}
}

// createPendingCertificate starts an external-issuer operation: generate the
// key + CSR, store it pending, and return the in-progress operation.
func (s *Service) createPendingCertificate(w http.ResponseWriter, r *http.Request, vault, name string, pol certPolicy, policyRaw json.RawMessage) {
	if _, err := s.Store.GetDeletedCert(vault, name); err == nil {
		writeKVErr(w, http.StatusConflict, "Conflict",
			"Certificate is in a deleted but recoverable state; recover or purge it first.")
		return
	}
	privDER, csrDER, kty, err := generateCSR(pol)
	if err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", err.Error())
		return
	}
	p := &store.PendingCert{
		Vault: vault, Name: name, PrivateDER: privDER, CSRDER: csrDER, Kty: kty,
		Issuer: pol.IssuerRef.Name,
	}
	if len(policyRaw) > 0 {
		p.PolicyJSON = string(policyRaw)
	}
	if err := s.Store.SetPendingCert(p); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, s.pendingOperation(r, p))
}

// getCertificateOperation is GET /certificates/{name}/pending. A pending
// external-issuer request reports "inProgress" with its CSR; an issued cert
// reports "completed".
func (s *Service) getCertificateOperation(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	if p, err := s.Store.GetPendingCert(vault, name); err == nil {
		writeJSON(w, http.StatusOK, s.pendingOperation(r, p))
		return
	}
	if _, err := s.Store.GetCert(vault, name); err != nil {
		certNotFound(w, name)
		return
	}
	writeJSON(w, http.StatusOK, s.certOperation(r, name, "completed"))
}

// mergeCertificate is POST /certificates/{name}/pending/merge: complete a
// pending operation with the externally-signed certificate chain (x5c). The
// leaf's public key must match the pending key; the emulator then binds the
// stored private key to the signed cert and materializes the linked
// key/secret.
func (s *Service) mergeCertificate(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	p, err := s.Store.GetPendingCert(vault, name)
	if errors.Is(err, store.ErrNotFound) {
		writeKVErr(w, http.StatusNotFound, "PendingCertificateNotFound",
			fmt.Sprintf("No pending certificate operation for %s to merge.", name))
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	var body struct {
		X5C  [][]byte          `json:"x5c"`
		Tags map[string]string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.X5C) == 0 {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The request must include the signed certificate chain (x5c).")
		return
	}
	leaf, err := x509.ParseCertificate(body.X5C[0])
	if err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The merged certificate is not valid DER.")
		return
	}
	priv, err := parseKey(p.PrivateDER)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !samePublicKey(leaf.PublicKey, publicOf(priv)) {
		writeKVErr(w, http.StatusBadRequest, "BadParameter",
			"The merged certificate's public key does not match the pending certificate's key.")
		return
	}
	sum := sha1.Sum(body.X5C[0])
	nbf, exp := leaf.NotBefore.Unix(), leaf.NotAfter.Unix()
	cv := &store.CertVersion{
		Vault: vault, Name: name, CerDER: base64.StdEncoding.EncodeToString(body.X5C[0]),
		PrivateDER: p.PrivateDER, Thumbprint: base64.RawURLEncoding.EncodeToString(sum[:]),
		PolicyJSON: p.PolicyJSON, Enabled: true, NBF: &nbf, Exp: &exp,
	}
	if body.Tags != nil {
		raw, _ := json.Marshal(body.Tags)
		cv.TagsJSON = string(raw)
	}
	if err := s.Store.SetCert(cv); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if err := s.materialize(vault, name, cv, p.Kty); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if err := s.Store.DeletePendingCert(vault, name); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, s.certBundle(r, cv))
}

func (s *Service) loadCert(w http.ResponseWriter, vault, name, version string) *store.CertVersion {
	var v *store.CertVersion
	var err error
	if version == "" {
		v, err = s.Store.GetCert(vault, name)
	} else {
		v, err = s.Store.GetCertVersion(vault, name, version)
	}
	if errors.Is(err, store.ErrNotFound) {
		certNotFound(w, name)
		return nil
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return nil
	}
	return v
}

func (s *Service) getCertificate(w http.ResponseWriter, r *http.Request, vault string) {
	if v := s.loadCert(w, vault, r.PathValue("name"), r.PathValue("version")); v != nil {
		writeJSON(w, http.StatusOK, s.certBundle(r, v))
	}
}

func (s *Service) getCertificatePolicy(w http.ResponseWriter, r *http.Request, vault string) {
	if v := s.loadCert(w, vault, r.PathValue("name"), ""); v != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(v.PolicyJSON))
	}
}

// importCertificate is POST /certificates/{name}/import: a caller-supplied
// PFX (PKCS#12) or PEM in the "value" field.
func (s *Service) importCertificate(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	var body struct {
		Value    string            `json:"value"`
		Password string            `json:"pwd"`
		Policy   json.RawMessage   `json:"policy"`
		Tags     map[string]string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Value == "" {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The request body must include a certificate value.")
		return
	}
	cerDER, privDER, thumb, nbf, exp, kty, err := parseImport(body.Value, body.Password)
	if err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", err.Error())
		return
	}
	cv := &store.CertVersion{
		Vault: vault, Name: name, CerDER: cerDER, PrivateDER: privDER, Thumbprint: thumb,
		Enabled: true, NBF: &nbf, Exp: &exp,
	}
	if len(body.Policy) > 0 {
		cv.PolicyJSON = string(body.Policy)
	}
	if body.Tags != nil {
		raw, _ := json.Marshal(body.Tags)
		cv.TagsJSON = string(raw)
	}
	if err := s.Store.SetCert(cv); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeKVErr(w, http.StatusConflict, "Conflict", "Certificate is in a deleted but recoverable state.")
			return
		}
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if privDER != "" {
		if err := s.materialize(vault, name, cv, kty); err != nil {
			writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, s.certBundle(r, cv))
}

func (s *Service) certItem(r *http.Request, v *store.CertVersion, versioned bool) map[string]any {
	id := fmt.Sprintf("%s/certificates/%s", s.baseURL(r), v.Name)
	if versioned {
		id += "/" + v.Version
	}
	return map[string]any{"id": id, "x5t": v.Thumbprint, "attributes": s.certAttrs(v)}
}

func (s *Service) listCertificates(w http.ResponseWriter, r *http.Request, vault string) {
	vs, err := s.Store.ListCerts(vault)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		items = append(items, s.certItem(r, v, false))
	}
	s.paged(w, r, "/certificates", items)
}

func (s *Service) listCertificateVersions(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	vs, err := s.Store.ListCertVersions(vault, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			certNotFound(w, name)
			return
		}
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		items = append(items, s.certItem(r, v, true))
	}
	s.paged(w, r, "/certificates/"+name+"/versions", items)
}

// ---- soft delete ----

func (s *Service) deleteCertificate(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	d, err := s.Store.DeleteCert(vault, name, s.Cfg.SoftDeleteRetentionDays)
	if errors.Is(err, store.ErrNotFound) {
		certNotFound(w, name)
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	v, err := s.Store.LatestCertIncludingDeleted(vault, name)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	b := s.certBundle(r, v)
	b["recoveryId"] = fmt.Sprintf("%s/deletedcertificates/%s", s.baseURL(r), name)
	b["deletedDate"] = d.DeletedAt
	b["scheduledPurgeDate"] = d.PurgeAt
	writeJSON(w, http.StatusOK, b)
}

func (s *Service) getDeletedCertificate(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	d, err := s.Store.GetDeletedCert(vault, name)
	if errors.Is(err, store.ErrNotFound) {
		certNotFound(w, name)
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	v, err := s.Store.LatestCertIncludingDeleted(vault, name)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	b := s.certBundle(r, v)
	b["recoveryId"] = fmt.Sprintf("%s/deletedcertificates/%s", s.baseURL(r), name)
	b["deletedDate"] = d.DeletedAt
	b["scheduledPurgeDate"] = d.PurgeAt
	writeJSON(w, http.StatusOK, b)
}

func (s *Service) listDeletedCertificates(w http.ResponseWriter, r *http.Request, vault string) {
	ds, err := s.Store.ListDeletedCerts(vault)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(ds))
	for _, d := range ds {
		v, err := s.Store.LatestCertIncludingDeleted(vault, d.Name)
		if err != nil {
			writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		it := s.certItem(r, v, false)
		it["recoveryId"] = fmt.Sprintf("%s/deletedcertificates/%s", s.baseURL(r), d.Name)
		it["scheduledPurgeDate"] = d.PurgeAt
		items = append(items, it)
	}
	s.paged(w, r, "/deletedcertificates", items)
}

func (s *Service) purgeCertificate(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	if _, err := s.Store.GetDeletedCert(vault, name); errors.Is(err, store.ErrNotFound) {
		certNotFound(w, name)
		return
	} else if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if err := s.Store.PurgeCert(vault, name); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) recoverCertificate(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	if _, err := s.Store.GetDeletedCert(vault, name); errors.Is(err, store.ErrNotFound) {
		certNotFound(w, name)
		return
	} else if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if err := s.Store.RecoverCert(vault, name); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	v, err := s.Store.GetCert(vault, name)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.certBundle(r, v))
}
