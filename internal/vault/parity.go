package vault

// P4 parity surface: the secondary key/certificate operations the Azure SDKs
// expose beyond core CRUD — GetRandomBytes, key import, key/certificate
// backup+restore, key rotation policy, certificate update/policy-update, and
// the certificate issuers and contacts sub-resources. These round out
// feature parity with the reference emulator while keeping our real-auth and
// real-crypto posture.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/store"
)

// ---- GetRandomBytes (POST /rng) ----

func (s *Service) getRandomBytes(w http.ResponseWriter, r *http.Request, _ string) {
	var body struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The request body must include count.")
		return
	}
	b, err := randomBytes(body.Count)
	if err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"value": b64u(b)})
}

// ---- key import (PUT /keys/{name}) ----

func (s *Service) importKey(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	var body struct {
		Key        jwkImport         `json:"key"`
		Attributes *attributes       `json:"attributes"`
		Tags       map[string]string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Key.Kty == "" {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The request body must include a key with kty.")
		return
	}
	der, kty, crv, err := importJWK(body.Key)
	if err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", err.Error())
		return
	}
	v := &store.KeyVersion{Vault: vault, Name: name, Kty: kty, Crv: crv, PrivateDER: der, Enabled: true}
	if len(body.Key.KeyOps) > 0 {
		raw, _ := json.Marshal(body.Key.KeyOps)
		v.KeyOpsJSON = string(raw)
	}
	if body.Attributes != nil {
		if body.Attributes.Enabled != nil {
			v.Enabled = *body.Attributes.Enabled
		}
		v.NBF, v.Exp = body.Attributes.NBF, body.Attributes.Exp
	}
	if body.Tags != nil {
		raw, _ := json.Marshal(body.Tags)
		v.TagsJSON = string(raw)
	}
	if err := s.Store.SetKey(v); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeKVErr(w, http.StatusConflict, "Conflict",
				"Key is currently in a deleted but recoverable state; recover or purge it first.")
			return
		}
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if b, ok := s.keyBundle(w, r, v); ok {
		writeJSON(w, http.StatusOK, b)
	}
}

// updateKeyLatest is PATCH /keys/{name}: patch the newest version.
func (s *Service) updateKeyLatest(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	v, err := s.Store.GetKey(vault, name)
	if errors.Is(err, store.ErrNotFound) {
		keyNotFound(w, name)
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	s.patchKey(w, r, v)
}

// ---- key backup / restore ----

type keyBackupBlob struct {
	Name     string              `json:"name"`
	Versions []*store.KeyVersion `json:"versions"`
}

func (s *Service) backupKey(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	vs, err := s.Store.ListKeyVersions(vault, name)
	if err != nil || len(vs) == 0 {
		keyNotFound(w, name)
		return
	}
	raw, err := json.Marshal(keyBackupBlob{Name: name, Versions: vs})
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"value": base64.RawURLEncoding.EncodeToString(raw)})
}

func (s *Service) restoreKey(w http.ResponseWriter, r *http.Request, vault string) {
	raw, ok := decodeBackup(w, r)
	if !ok {
		return
	}
	var blob keyBackupBlob
	if err := json.Unmarshal(raw, &blob); err != nil || blob.Name == "" || len(blob.Versions) == 0 {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The backup blob is malformed.")
		return
	}
	if _, err := s.Store.GetKey(vault, blob.Name); err == nil {
		writeKVErr(w, http.StatusConflict, "Conflict", "Key "+blob.Name+" already exists in this vault.")
		return
	}
	for _, v := range blob.Versions {
		v.Vault, v.Name = vault, blob.Name
		if err := s.Store.SetKey(v); err != nil {
			writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
	}
	cur, err := s.Store.GetKey(vault, blob.Name)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if b, ok := s.keyBundle(w, r, cur); ok {
		writeJSON(w, http.StatusOK, b)
	}
}

// ---- key release (Secure Key Release) ----

// releaseKey is POST /keys/{name}/{version}/release. It returns a signed JWS
// carrying the released key's public JWK — the SDK's ReleaseKey path. Real
// attestation is out of scope (there is no HSM/enclave), so the emulator
// releases any enabled key, like the reference emulator; the token is
// nonetheless a genuine signed object.
func (s *Service) releaseKey(w http.ResponseWriter, r *http.Request, vault string) {
	v := s.loadKey(w, vault, r.PathValue("name"), r.PathValue("version"))
	if v == nil {
		return
	}
	var body struct {
		Target string `json:"target"`
		Nonce  string `json:"nonce"`
		Enc    string `json:"enc"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	priv, err := parseKey(v.PrivateDER)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	kid := fmt.Sprintf("%s/keys/%s/%s", s.baseURL(r), v.Name, v.Version)
	jwk, err := publicJWK(priv, kid, v.Kty, keyOps(v))
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	claims := map[string]any{
		"response": map[string]any{"key": map[string]any{"key": jwk, "attributes": s.keyAttrs(v)}},
		"iat":      s.Store.Now(),
	}
	if body.Nonce != "" {
		claims["nonce"] = body.Nonce
	}
	token, err := buildReleaseToken(claims)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"value": token})
}

// ---- key rotation policy ----

func (s *Service) getKeyRotationPolicy(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	if _, err := s.Store.GetKey(vault, name); errors.Is(err, store.ErrNotFound) {
		keyNotFound(w, name)
		return
	} else if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	js, err := s.Store.GetKeyRotationPolicy(vault, name)
	if errors.Is(err, store.ErrNotFound) {
		// No policy set: return the documented default (rotation disabled).
		writeJSON(w, http.StatusOK, s.defaultRotationPolicy(r, name))
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(js))
}

func (s *Service) setKeyRotationPolicy(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	if _, err := s.Store.GetKey(vault, name); errors.Is(err, store.ErrNotFound) {
		keyNotFound(w, name)
		return
	} else if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	var doc map[string]any
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "Malformed JSON body.")
		return
	}
	doc["id"] = fmt.Sprintf("%s/keys/%s/rotationpolicy", s.baseURL(r), name)
	raw, _ := json.Marshal(doc)
	if err := s.Store.SetKeyRotationPolicy(vault, name, string(raw)); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *Service) defaultRotationPolicy(r *http.Request, name string) map[string]any {
	return map[string]any{
		"id":              fmt.Sprintf("%s/keys/%s/rotationpolicy", s.baseURL(r), name),
		"lifetimeActions": []any{},
		"attributes":      map[string]any{},
	}
}

// ---- certificate backup / restore ----

type certBackupBlob struct {
	Name     string               `json:"name"`
	Versions []*store.CertVersion `json:"versions"`
}

func (s *Service) backupCertificate(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	vs, err := s.Store.ListCertVersions(vault, name)
	if err != nil || len(vs) == 0 {
		certNotFound(w, name)
		return
	}
	raw, err := json.Marshal(certBackupBlob{Name: name, Versions: vs})
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"value": base64.RawURLEncoding.EncodeToString(raw)})
}

func (s *Service) restoreCertificate(w http.ResponseWriter, r *http.Request, vault string) {
	raw, ok := decodeBackup(w, r)
	if !ok {
		return
	}
	var blob certBackupBlob
	if err := json.Unmarshal(raw, &blob); err != nil || blob.Name == "" || len(blob.Versions) == 0 {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The backup blob is malformed.")
		return
	}
	if _, err := s.Store.GetCert(vault, blob.Name); err == nil {
		writeKVErr(w, http.StatusConflict, "Conflict", "Certificate "+blob.Name+" already exists in this vault.")
		return
	}
	for _, v := range blob.Versions {
		v.Vault, v.Name = vault, blob.Name
		if err := s.Store.SetCert(v); err != nil {
			writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		// Re-materialize the linked key/secret, as issuance did — but only if
		// they aren't already present. Certificate deletion doesn't cascade to
		// the linked key/secret in the emulator, so a delete→purge→restore
		// cycle can leave them behind; re-inserting the same version would
		// violate the uniqueness constraint.
		if v.PrivateDER == "" {
			continue
		}
		if _, err := s.Store.GetKeyVersion(vault, blob.Name, v.Version); err == nil {
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		priv, perr := parseKey(v.PrivateDER)
		if perr != nil {
			writeKVErr(w, http.StatusInternalServerError, "InternalServerError", perr.Error())
			return
		}
		if err := s.materialize(vault, blob.Name, v, ktyOf(priv)); err != nil {
			writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
	}
	cur, err := s.Store.GetCert(vault, blob.Name)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.certBundle(r, cur))
}

// ---- certificate update + policy update ----

// updateCertificate is PATCH /certificates/{name}/{version} (version optional):
// updates enabled/tags on the version and, when present, the policy.
func (s *Service) updateCertificate(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	v := s.loadCert(w, vault, name, r.PathValue("version"))
	if v == nil {
		return
	}
	var body struct {
		Attributes *attributes       `json:"attributes"`
		Policy     json.RawMessage   `json:"policy"`
		Tags       map[string]string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "Malformed JSON body.")
		return
	}
	if body.Attributes != nil && body.Attributes.Enabled != nil {
		v.Enabled = *body.Attributes.Enabled
	}
	if body.Tags != nil {
		raw, _ := json.Marshal(body.Tags)
		v.TagsJSON = string(raw)
	}
	if err := s.Store.UpdateCertVersion(v); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if len(body.Policy) > 0 {
		if err := s.Store.UpdateCertPolicy(vault, name, string(body.Policy)); err != nil {
			writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		v.PolicyJSON = string(body.Policy)
	}
	writeJSON(w, http.StatusOK, s.certBundle(r, v))
}

// updateCertificatePolicy is PATCH /certificates/{name}/policy.
func (s *Service) updateCertificatePolicy(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	if _, err := s.Store.GetCert(vault, name); errors.Is(err, store.ErrNotFound) {
		certNotFound(w, name)
		return
	} else if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	raw, err := readRawJSON(r)
	if err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "Malformed JSON body.")
		return
	}
	if err := s.Store.UpdateCertPolicy(vault, name, string(raw)); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// ---- certificate issuers ----

func (s *Service) issuerBundle(r *http.Request, name, js string) map[string]any {
	var doc map[string]any
	_ = json.Unmarshal([]byte(js), &doc)
	if doc == nil {
		doc = map[string]any{}
	}
	doc["id"] = fmt.Sprintf("%s/certificates/issuers/%s", s.baseURL(r), name)
	return doc
}

func (s *Service) setCertIssuer(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	raw, err := readRawJSON(r)
	if err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "Malformed JSON body.")
		return
	}
	if err := s.Store.SetCertIssuer(vault, name, string(raw)); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.issuerBundle(r, name, string(raw)))
}

func (s *Service) getCertIssuer(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	js, err := s.Store.GetCertIssuer(vault, name)
	if errors.Is(err, store.ErrNotFound) {
		issuerNotFound(w, name)
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.issuerBundle(r, name, js))
}

func (s *Service) deleteCertIssuer(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	js, err := s.Store.DeleteCertIssuer(vault, name)
	if errors.Is(err, store.ErrNotFound) {
		issuerNotFound(w, name)
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.issuerBundle(r, name, js))
}

func (s *Service) listCertIssuers(w http.ResponseWriter, r *http.Request, vault string) {
	issuers, err := s.Store.ListCertIssuers(vault)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(issuers))
	for _, it := range issuers {
		var doc map[string]any
		_ = json.Unmarshal([]byte(it.JSON), &doc)
		entry := map[string]any{"id": fmt.Sprintf("%s/certificates/issuers/%s", s.baseURL(r), it.Name)}
		if p, ok := doc["provider"]; ok {
			entry["provider"] = p
		}
		items = append(items, entry)
	}
	s.paged(w, r, "/certificates/issuers", items)
}

func issuerNotFound(w http.ResponseWriter, name string) {
	writeKVErr(w, http.StatusNotFound, "IssuerNotFound",
		fmt.Sprintf("An issuer with (name) %s was not found in this key vault.", name))
}

// ---- certificate contacts ----

func (s *Service) setCertContacts(w http.ResponseWriter, r *http.Request, vault string) {
	raw, err := readRawJSON(r)
	if err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "Malformed JSON body.")
		return
	}
	if err := s.Store.SetCertContacts(vault, string(raw)); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.contactsBundle(r, string(raw)))
}

func (s *Service) getCertContacts(w http.ResponseWriter, r *http.Request, vault string) {
	js, err := s.Store.GetCertContacts(vault)
	if errors.Is(err, store.ErrNotFound) {
		writeKVErr(w, http.StatusNotFound, "ContactsNotFound", "No contacts are set on this key vault.")
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.contactsBundle(r, js))
}

func (s *Service) deleteCertContacts(w http.ResponseWriter, r *http.Request, vault string) {
	js, err := s.Store.DeleteCertContacts(vault)
	if errors.Is(err, store.ErrNotFound) {
		writeKVErr(w, http.StatusNotFound, "ContactsNotFound", "No contacts are set on this key vault.")
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.contactsBundle(r, js))
}

func (s *Service) contactsBundle(r *http.Request, js string) map[string]any {
	var doc map[string]any
	_ = json.Unmarshal([]byte(js), &doc)
	if doc == nil {
		doc = map[string]any{}
	}
	doc["id"] = fmt.Sprintf("%s/certificates/contacts", s.baseURL(r))
	return doc
}

// ---- shared helpers ----

// decodeBackup reads and base64url-decodes a {"value": "..."} backup body.
func decodeBackup(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Value == "" {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The request body must include a backup blob value.")
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body.Value)
	if err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The backup blob is not valid base64url.")
		return nil, false
	}
	return raw, true
}

// readRawJSON reads the body and validates it is well-formed JSON, returning
// the canonical bytes.
func readRawJSON(r *http.Request) (json.RawMessage, error) {
	var doc json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}
