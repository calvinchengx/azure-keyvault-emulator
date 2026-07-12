package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/store"
)

// attributes is the wire shape of secret attributes (7.5).
type attributes struct {
	Enabled         *bool  `json:"enabled,omitempty"`
	NBF             *int64 `json:"nbf,omitempty"`
	Exp             *int64 `json:"exp,omitempty"`
	Created         int64  `json:"created,omitempty"`
	Updated         int64  `json:"updated,omitempty"`
	RecoveryLevel   string `json:"recoveryLevel,omitempty"`
	RecoverableDays int    `json:"recoverableDays,omitempty"`
}

func (s *Service) attrsOf(v *store.SecretVersion) attributes {
	return attributes{
		Enabled: &v.Enabled, NBF: v.NBF, Exp: v.Exp,
		Created: v.CreatedAt, Updated: v.UpdatedAt,
		RecoveryLevel: "Recoverable+Purgeable", RecoverableDays: s.Cfg.SoftDeleteRetentionDays,
	}
}

func tags(v *store.SecretVersion) map[string]string {
	out := map[string]string{}
	_ = json.Unmarshal([]byte(v.TagsJSON), &out)
	return out
}

// bundle renders a secret bundle; withValue=false for update/list responses.
func (s *Service) bundle(r *http.Request, v *store.SecretVersion, withValue bool) map[string]any {
	b := map[string]any{
		"id":         fmt.Sprintf("%s/secrets/%s/%s", s.baseURL(r), v.Name, v.Version),
		"attributes": s.attrsOf(v),
		"tags":       tags(v),
	}
	if v.ContentType != "" {
		b["contentType"] = v.ContentType
	}
	if withValue {
		b["value"] = v.Value
	}
	return b
}

// item renders a list entry (unversioned id, no value).
func (s *Service) item(r *http.Request, v *store.SecretVersion, versioned bool) map[string]any {
	id := fmt.Sprintf("%s/secrets/%s", s.baseURL(r), v.Name)
	if versioned {
		id += "/" + v.Version
	}
	it := map[string]any{"id": id, "attributes": s.attrsOf(v), "tags": tags(v)}
	if v.ContentType != "" {
		it["contentType"] = v.ContentType
	}
	return it
}

// secretNotFound is the canonical 404.
func secretNotFound(w http.ResponseWriter, name string) {
	writeKVErr(w, http.StatusNotFound, "SecretNotFound",
		fmt.Sprintf("A secret with (name/id) %s was not found in this key vault.", name))
}

type secretBody struct {
	Value       string            `json:"value"`
	ContentType string            `json:"contentType"`
	Attributes  *attributes       `json:"attributes"`
	Tags        map[string]string `json:"tags"`
}

// setSecret is PUT /secrets/{name}: always a new version.
func (s *Service) setSecret(w http.ResponseWriter, r *http.Request, vault string) {
	var body secretBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Value == "" {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The request body must include a non-empty value.")
		return
	}
	v := &store.SecretVersion{Vault: vault, Name: r.PathValue("name"), Value: body.Value,
		ContentType: body.ContentType, Enabled: true}
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
	if err := s.Store.SetSecret(v); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeKVErr(w, http.StatusConflict, "Conflict",
				"Secret is currently in a deleted but recoverable state; recover or purge it first.")
			return
		}
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.bundle(r, v, true))
}

// getCurrent loads the newest version, mapping absence to the 404 shape and
// enabled=false to the documented 403.
func (s *Service) getCurrent(w http.ResponseWriter, vault, name string) *store.SecretVersion {
	v, err := s.Store.GetSecret(vault, name)
	if errors.Is(err, store.ErrNotFound) {
		secretNotFound(w, name)
		return nil
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return nil
	}
	if !v.Enabled {
		writeKVErr(w, http.StatusForbidden, "Forbidden", "Operation get is not allowed on a disabled secret.")
		return nil
	}
	return v
}

func (s *Service) getSecret(w http.ResponseWriter, r *http.Request, vault string) {
	if v := s.getCurrent(w, vault, r.PathValue("name")); v != nil {
		writeJSON(w, http.StatusOK, s.bundle(r, v, true))
	}
}

func (s *Service) getSecretVersion(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	v, err := s.Store.GetSecretVersion(vault, name, r.PathValue("version"))
	if errors.Is(err, store.ErrNotFound) {
		secretNotFound(w, name)
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !v.Enabled {
		writeKVErr(w, http.StatusForbidden, "Forbidden", "Operation get is not allowed on a disabled secret.")
		return
	}
	writeJSON(w, http.StatusOK, s.bundle(r, v, true))
}

// updateSecret is PATCH /secrets/{name}/{version}: attributes/tags only; the
// response carries no value, like real Key Vault.
func (s *Service) updateSecret(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	v, err := s.Store.GetSecretVersion(vault, name, r.PathValue("version"))
	if errors.Is(err, store.ErrNotFound) {
		secretNotFound(w, name)
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	var body secretBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "Malformed JSON body.")
		return
	}
	if body.ContentType != "" {
		v.ContentType = body.ContentType
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
	if err := s.Store.UpdateSecretVersion(v); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.bundle(r, v, false))
}

// paged renders {value:[...], nextLink} honoring maxresults + $skiptoken.
func (s *Service) paged(w http.ResponseWriter, r *http.Request, path string, items []map[string]any) {
	max := 25
	if m, err := strconv.Atoi(r.URL.Query().Get("maxresults")); err == nil && m > 0 && m <= 25 {
		max = m
	}
	skip, _ := strconv.Atoi(r.URL.Query().Get("$skiptoken"))
	if skip < 0 || skip > len(items) {
		skip = len(items)
	}
	end := skip + max
	var next any
	if end < len(items) {
		next = fmt.Sprintf("%s%s?api-version=%s&maxresults=%d&$skiptoken=%d",
			s.baseURL(r), path, r.URL.Query().Get("api-version"), max, end)
	} else {
		end = len(items)
	}
	page := items[skip:end]
	if page == nil {
		page = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": page, "nextLink": next})
}

func (s *Service) listSecrets(w http.ResponseWriter, r *http.Request, vault string) {
	vs, err := s.Store.ListSecrets(vault)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		items = append(items, s.item(r, v, false))
	}
	s.paged(w, r, "/secrets", items)
}

func (s *Service) listSecretVersions(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	vs, err := s.Store.ListSecretVersions(vault, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			secretNotFound(w, name)
			return
		}
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		items = append(items, s.item(r, v, true))
	}
	s.paged(w, r, "/secrets/"+name+"/versions", items)
}

// ---- soft delete ----

func (s *Service) deletedBundle(r *http.Request, d *store.DeletedSecret, v *store.SecretVersion) map[string]any {
	b := s.bundle(r, v, true)
	b["recoveryId"] = fmt.Sprintf("%s/deletedsecrets/%s", s.baseURL(r), d.Name)
	b["deletedDate"] = d.DeletedAt
	b["scheduledPurgeDate"] = d.PurgeAt
	return b
}

func (s *Service) deleteSecret(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	d, err := s.Store.DeleteSecret(vault, name, s.Cfg.SoftDeleteRetentionDays)
	if errors.Is(err, store.ErrNotFound) {
		secretNotFound(w, name)
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	v, err := s.Store.LatestVersionIncludingDeleted(vault, name)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.deletedBundle(r, d, v))
}

func (s *Service) getDeletedSecret(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	d, err := s.Store.GetDeletedSecret(vault, name)
	if errors.Is(err, store.ErrNotFound) {
		secretNotFound(w, name)
		return
	}
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	v, err := s.Store.LatestVersionIncludingDeleted(vault, name)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.deletedBundle(r, d, v))
}

func (s *Service) listDeletedSecrets(w http.ResponseWriter, r *http.Request, vault string) {
	ds, err := s.Store.ListDeletedSecrets(vault)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(ds))
	for _, d := range ds {
		v, err := s.Store.LatestVersionIncludingDeleted(vault, d.Name)
		if err != nil {
			writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		it := s.item(r, v, false)
		it["recoveryId"] = fmt.Sprintf("%s/deletedsecrets/%s", s.baseURL(r), d.Name)
		it["deletedDate"] = d.DeletedAt
		it["scheduledPurgeDate"] = d.PurgeAt
		items = append(items, it)
	}
	s.paged(w, r, "/deletedsecrets", items)
}

func (s *Service) purgeSecret(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	if _, err := s.Store.GetDeletedSecret(vault, name); errors.Is(err, store.ErrNotFound) {
		secretNotFound(w, name)
		return
	} else if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if err := s.Store.PurgeSecret(vault, name); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) recoverSecret(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	if _, err := s.Store.GetDeletedSecret(vault, name); errors.Is(err, store.ErrNotFound) {
		secretNotFound(w, name)
		return
	} else if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if err := s.Store.RecoverSecret(vault, name); err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	v, err := s.Store.GetSecret(vault, name)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.bundle(r, v, false))
}

// ---- backup / restore ----

// backupBlob is the opaque backup payload: every version of one name.
type backupBlob struct {
	Name     string                 `json:"name"`
	Versions []*store.SecretVersion `json:"versions"`
}

func (s *Service) backupSecret(w http.ResponseWriter, r *http.Request, vault string) {
	name := r.PathValue("name")
	vs, err := s.Store.ListSecretVersions(vault, name)
	if err != nil || len(vs) == 0 {
		secretNotFound(w, name)
		return
	}
	raw, err := json.Marshal(backupBlob{Name: name, Versions: vs})
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"value": base64.RawURLEncoding.EncodeToString(raw)})
}

func (s *Service) restoreSecret(w http.ResponseWriter, r *http.Request, vault string) {
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Value == "" {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The request body must include a backup blob value.")
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(body.Value)
	if err != nil {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The backup blob is not valid base64url.")
		return
	}
	var blob backupBlob
	if err := json.Unmarshal(raw, &blob); err != nil || blob.Name == "" || len(blob.Versions) == 0 {
		writeKVErr(w, http.StatusBadRequest, "BadParameter", "The backup blob is malformed.")
		return
	}
	if _, err := s.Store.GetSecret(vault, blob.Name); err == nil {
		writeKVErr(w, http.StatusConflict, "Conflict", "Secret "+blob.Name+" already exists in this vault.")
		return
	}
	for _, v := range blob.Versions {
		v.Vault, v.Name = vault, blob.Name
		if err := s.Store.SetSecret(v); err != nil {
			writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
	}
	cur, err := s.Store.GetSecret(vault, blob.Name)
	if err != nil {
		writeKVErr(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.bundle(r, cur, true))
}
