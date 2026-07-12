package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/store"
)

var defaultKeyOps = []string{"sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey"}

func keyOps(v *store.KeyVersion) []string {
	var ops []string
	_ = json.Unmarshal([]byte(v.KeyOpsJSON), &ops)
	if len(ops) == 0 {
		ops = defaultKeyOps
	}
	return ops
}

func keyTags(v *store.KeyVersion) map[string]string {
	out := map[string]string{}
	_ = json.Unmarshal([]byte(v.TagsJSON), &out)
	return out
}

func (s *Service) keyAttrs(v *store.KeyVersion) attributes {
	return attributes{
		Enabled: &v.Enabled, NBF: v.NBF, Exp: v.Exp,
		Created: v.CreatedAt, Updated: v.UpdatedAt,
		RecoveryLevel: "Recoverable+Purgeable", RecoverableDays: s.Cfg.SoftDeleteRetentionDays,
	}
}

// keyBundle renders {key: <public JWK>, attributes, tags}.
func (s *Service) keyBundle(w http.ResponseWriter, r *http.Request, v *store.KeyVersion) (map[string]any, bool) {
	priv, err := parseKey(v.PrivateDER)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return nil, false
	}
	kid := fmt.Sprintf("%s/keys/%s/%s", s.baseURL(r), v.Name, v.Version)
	jwk, err := publicJWK(priv, kid, v.Kty, keyOps(v))
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return nil, false
	}
	return map[string]any{"key": jwk, "attributes": s.keyAttrs(v), "tags": keyTags(v)}, true
}

func keyNotFound(w http.ResponseWriter, name string) {
	writeKVErr(w, http.StatusNotFound, "KeyNotFound",
		fmt.Sprintf("A key with (name/id) %s was not found in this key vault.", name))
}

// createKey is POST /keys/{name}/create.
func (s *Service) createKey(w http.ResponseWriter, r *http.Request, vault string) {
	var body struct {
		Kty        string            `json:"kty"`
		KeySize    int               `json:"key_size"`
		Crv        string            `json:"crv"`
		KeyOps     []string          `json:"key_ops"`
		Attributes *attributes       `json:"attributes"`
		Tags       map[string]string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Kty == "" {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The request body must include kty.")
		return
	}
	der, crv, err := generateKey(body.Kty, body.KeySize, body.Crv)
	if err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", err.Error())
		return
	}
	v := &store.KeyVersion{
		Vault: vault, Name: r.PathValue("name"), Kty: normalizeKty(body.Kty), Crv: crv,
		PrivateDER: der, Enabled: true,
	}
	if len(body.KeyOps) > 0 {
		raw, _ := json.Marshal(body.KeyOps)
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

func normalizeKty(kty string) string {
	if kty == "RSA-HSM" {
		return "RSA"
	}
	if kty == "EC-HSM" {
		return "EC"
	}
	return kty
}

// loadKey resolves name(+optional version) to a live, enabled key version.
func (s *Service) loadKey(w http.ResponseWriter, vault, name, version string) *store.KeyVersion {
	var v *store.KeyVersion
	var err error
	if version == "" {
		v, err = s.Store.GetKey(vault, name)
	} else {
		v, err = s.Store.GetKeyVersion(vault, name, version)
	}
	if errors.Is(err, store.ErrNotFound) {
		keyNotFound(w, name)
		return nil
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return nil
	}
	if !v.Enabled {
		writeKVErr(w, http.StatusForbidden, "Forbidden", "Operation is not allowed on a disabled key.")
		return nil
	}
	return v
}

func (s *Service) getKey(w http.ResponseWriter, r *http.Request, vault string) {
	if v := s.loadKey(w, vault, r.PathValue("name"), r.PathValue("version")); v != nil {
		if b, ok := s.keyBundle(w, r, v); ok {
			writeJSON(w, http.StatusOK, b)
		}
	}
}

// updateKey is PATCH /keys/{name}/{version}.
func (s *Service) updateKey(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	v, err := s.Store.GetKeyVersion(vault, name, r.PathValue("version"))
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

// patchKey applies an attribute/ops/tag PATCH body to an already-resolved key
// version and writes the bundle. Shared by the versioned and latest forms.
func (s *Service) patchKey(w http.ResponseWriter, r *http.Request, v *store.KeyVersion) {
	var body struct {
		KeyOps     []string          `json:"key_ops"`
		Attributes *attributes       `json:"attributes"`
		Tags       map[string]string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "Malformed JSON body.")
		return
	}
	if len(body.KeyOps) > 0 {
		raw, _ := json.Marshal(body.KeyOps)
		v.KeyOpsJSON = string(raw)
	}
	if body.Attributes != nil {
		if body.Attributes.Enabled != nil {
			v.Enabled = *body.Attributes.Enabled
		}
		if body.Attributes.NBF != nil {
			v.NBF = body.Attributes.NBF
		}
		if body.Attributes.Exp != nil {
			v.Exp = body.Attributes.Exp
		}
	}
	if body.Tags != nil {
		raw, _ := json.Marshal(body.Tags)
		v.TagsJSON = string(raw)
	}
	if err := s.Store.UpdateKeyVersion(v); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if b, ok := s.keyBundle(w, r, v); ok {
		writeJSON(w, http.StatusOK, b)
	}
}

// keyItem renders a list entry: {kid, attributes, tags}.
func (s *Service) keyItem(r *http.Request, v *store.KeyVersion, versioned bool) map[string]any {
	kid := fmt.Sprintf("%s/keys/%s", s.baseURL(r), v.Name)
	if versioned {
		kid += "/" + v.Version
	}
	return map[string]any{"kid": kid, "attributes": s.keyAttrs(v), "tags": keyTags(v)}
}

func (s *Service) listKeys(w http.ResponseWriter, r *http.Request, vault string) {
	vs, err := s.Store.ListKeys(vault)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		items = append(items, s.keyItem(r, v, false))
	}
	s.paged(w, r, "/keys", items)
}

func (s *Service) listKeyVersions(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	vs, err := s.Store.ListKeyVersions(vault, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			keyNotFound(w, name)
			return
		}
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		items = append(items, s.keyItem(r, v, true))
	}
	s.paged(w, r, "/keys/"+name+"/versions", items)
}

// ---- soft delete ----

func (s *Service) deletedKeyBundle(w http.ResponseWriter, r *http.Request, d *store.DeletedSecret, v *store.KeyVersion) (map[string]any, bool) {
	b, ok := s.keyBundle(w, r, v)
	if !ok {
		return nil, false
	}
	b["recoveryId"] = fmt.Sprintf("%s/deletedkeys/%s", s.baseURL(r), d.Name)
	b["deletedDate"] = d.DeletedAt
	b["scheduledPurgeDate"] = d.PurgeAt
	return b, true
}

func (s *Service) deleteKey(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	d, err := s.Store.DeleteKey(vault, name, s.Cfg.SoftDeleteRetentionDays)
	if errors.Is(err, store.ErrNotFound) {
		keyNotFound(w, name)
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	v, err := s.Store.LatestKeyIncludingDeleted(vault, name)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if b, ok := s.deletedKeyBundle(w, r, d, v); ok {
		writeJSON(w, http.StatusOK, b)
	}
}

func (s *Service) getDeletedKey(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	d, err := s.Store.GetDeletedKey(vault, name)
	if errors.Is(err, store.ErrNotFound) {
		keyNotFound(w, name)
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	v, err := s.Store.LatestKeyIncludingDeleted(vault, name)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if b, ok := s.deletedKeyBundle(w, r, d, v); ok {
		writeJSON(w, http.StatusOK, b)
	}
}

func (s *Service) listDeletedKeys(w http.ResponseWriter, r *http.Request, vault string) {
	ds, err := s.Store.ListDeletedKeys(vault)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(ds))
	for _, d := range ds {
		v, err := s.Store.LatestKeyIncludingDeleted(vault, d.Name)
		if err != nil {
			writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		it := s.keyItem(r, v, false)
		it["recoveryId"] = fmt.Sprintf("%s/deletedkeys/%s", s.baseURL(r), d.Name)
		it["deletedDate"] = d.DeletedAt
		it["scheduledPurgeDate"] = d.PurgeAt
		items = append(items, it)
	}
	s.paged(w, r, "/deletedkeys", items)
}

func (s *Service) purgeKey(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	if _, err := s.Store.GetDeletedKey(vault, name); errors.Is(err, store.ErrNotFound) {
		keyNotFound(w, name)
		return
	} else if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if err := s.Store.PurgeKey(vault, name); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) recoverKey(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	if _, err := s.Store.GetDeletedKey(vault, name); errors.Is(err, store.ErrNotFound) {
		keyNotFound(w, name)
		return
	} else if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if err := s.Store.RecoverKey(vault, name); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	v, err := s.Store.GetKey(vault, name)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if b, ok := s.keyBundle(w, r, v); ok {
		writeJSON(w, http.StatusOK, b)
	}
}

// ---- crypto operations ----

// cryptoOp handles sign/verify/encrypt/decrypt/wrapkey/unwrapkey — the op
// comes from the route. Wire values are base64url.
func (s *Service) cryptoOp(op string) handler {
	return func(w http.ResponseWriter, r *http.Request, vault string) {
		v := s.loadKey(w, vault, r.PathValue("name"), r.PathValue("version"))
		if v == nil {
			return
		}
		var body struct {
			Alg    string `json:"alg"`
			Value  string `json:"value"`
			Digest string `json:"digest"` // verify: some clients send digest+value
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Alg == "" || body.Value == "" {
			writeKVErr(w, http.StatusBadRequest, "BadParameter", "The request body must include alg and value.")
			return
		}
		value, err := base64.RawURLEncoding.DecodeString(body.Value)
		if err != nil {
			writeKVErr(w, http.StatusBadRequest, "BadParameter", "value is not valid base64url.")
			return
		}
		priv, err := parseKey(v.PrivateDER)
		if err != nil {
			writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		kid := fmt.Sprintf("%s/keys/%s/%s", s.baseURL(r), v.Name, v.Version)

		switch op {
		case "sign":
			sig, err := sign(priv, body.Alg, value)
			if err != nil {
				writeKVErr(w, http.StatusBadRequest, "BadParameter", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"kid": kid, "value": b64u(sig)})
		case "verify":
			digest, err := base64.RawURLEncoding.DecodeString(body.Digest)
			if err != nil {
				writeKVErr(w, http.StatusBadRequest, "BadParameter", "digest is not valid base64url.")
				return
			}
			ok, err := verify(priv, body.Alg, digest, value)
			if err != nil {
				writeKVErr(w, http.StatusBadRequest, "BadParameter", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"value": ok})
		case "encrypt", "wrapkey":
			out, err := encrypt(priv, body.Alg, value)
			if err != nil {
				writeKVErr(w, http.StatusBadRequest, "BadParameter", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"kid": kid, "value": b64u(out)})
		case "decrypt", "unwrapkey":
			out, err := decrypt(priv, body.Alg, value)
			if err != nil {
				writeKVErr(w, http.StatusBadRequest, "BadParameter", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"kid": kid, "value": b64u(out)})
		}
	}
}
