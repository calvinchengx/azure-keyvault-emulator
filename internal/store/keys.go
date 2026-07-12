package store

import (
	"database/sql"
	"errors"
)

// KeyVersion is one immutable version of a key. Private material is stored
// as PKCS#8 (base64) and never leaves the store — handlers derive the public
// JWK from it.
type KeyVersion struct {
	Vault      string
	Name       string
	Version    string
	Kty        string // RSA | EC
	Crv        string // EC curve name ("" for RSA)
	PrivateDER string // base64(PKCS#8)
	KeyOpsJSON string
	Enabled    bool
	NBF        *int64
	Exp        *int64
	TagsJSON   string
	CreatedAt  int64
	UpdatedAt  int64
}

const kvCols = `vault, name, version, kty, crv, private_der, key_ops_json, enabled, nbf, exp, tags_json, created_at, updated_at`

func scanKV(row interface{ Scan(...any) error }) (*KeyVersion, error) {
	v := &KeyVersion{}
	err := row.Scan(&v.Vault, &v.Name, &v.Version, &v.Kty, &v.Crv, &v.PrivateDER,
		&v.KeyOpsJSON, &v.Enabled, &v.NBF, &v.Exp, &v.TagsJSON, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// SetKey creates a new key version; ErrConflict while the name is soft-deleted.
func (s *Store) SetKey(v *KeyVersion) error {
	if _, err := s.GetDeletedKey(v.Vault, v.Name); err == nil {
		return ErrConflict
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	if v.Version == "" {
		v.Version = NewVersionID()
	}
	now := s.Now()
	v.CreatedAt, v.UpdatedAt = now, now
	if v.TagsJSON == "" {
		v.TagsJSON = "{}"
	}
	if v.KeyOpsJSON == "" {
		v.KeyOpsJSON = "[]"
	}
	_, err := s.db.Exec(`INSERT INTO key_versions (`+kvCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		v.Vault, v.Name, v.Version, v.Kty, v.Crv, v.PrivateDER, v.KeyOpsJSON,
		v.Enabled, v.NBF, v.Exp, v.TagsJSON, v.CreatedAt, v.UpdatedAt)
	return err
}

// GetKey returns the newest version of a live name.
func (s *Store) GetKey(vault, name string) (*KeyVersion, error) {
	if _, err := s.GetDeletedKey(vault, name); err == nil {
		return nil, ErrNotFound
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return scanKV(s.db.QueryRow(`SELECT `+kvCols+` FROM key_versions
WHERE vault = ? AND name = ? ORDER BY created_at DESC, rowid DESC LIMIT 1`, vault, name))
}

// GetKeyVersion returns one specific version of a live name.
func (s *Store) GetKeyVersion(vault, name, version string) (*KeyVersion, error) {
	if _, err := s.GetDeletedKey(vault, name); err == nil {
		return nil, ErrNotFound
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return scanKV(s.db.QueryRow(`SELECT `+kvCols+` FROM key_versions
WHERE vault = ? AND name = ? AND version = ?`, vault, name, version))
}

// UpdateKeyVersion applies attribute/ops/tag changes.
func (s *Store) UpdateKeyVersion(v *KeyVersion) error {
	v.UpdatedAt = s.Now()
	res, err := s.db.Exec(`UPDATE key_versions
SET key_ops_json = ?, enabled = ?, nbf = ?, exp = ?, tags_json = ?, updated_at = ?
WHERE vault = ? AND name = ? AND version = ?`,
		v.KeyOpsJSON, v.Enabled, v.NBF, v.Exp, v.TagsJSON, v.UpdatedAt, v.Vault, v.Name, v.Version)
	if err != nil {
		return err
	}
	return oneRow(res)
}

// ListKeys returns the newest version per live name.
func (s *Store) ListKeys(vault string) ([]*KeyVersion, error) {
	rows, err := s.db.Query(`
SELECT `+kvCols+` FROM key_versions kv
WHERE vault = ?
  AND NOT EXISTS (SELECT 1 FROM deleted_keys d WHERE d.vault = kv.vault AND d.name = kv.name)
  AND rowid = (SELECT MAX(rowid) FROM key_versions x WHERE x.vault = kv.vault AND x.name = kv.name)
ORDER BY name`, vault)
	if err != nil {
		return nil, err
	}
	return collectKeys(rows)
}

// ListKeyVersions returns all versions of a live name, oldest first.
func (s *Store) ListKeyVersions(vault, name string) ([]*KeyVersion, error) {
	if _, err := s.GetDeletedKey(vault, name); err == nil {
		return nil, ErrNotFound
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT `+kvCols+` FROM key_versions
WHERE vault = ? AND name = ? ORDER BY rowid`, vault, name)
	if err != nil {
		return nil, err
	}
	return collectKeys(rows)
}

func collectKeys(rows *sql.Rows) ([]*KeyVersion, error) {
	defer rows.Close()
	var out []*KeyVersion
	for rows.Next() {
		v, err := scanKV(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---- soft delete (same clock semantics as secrets) ----

// DeleteKey soft-deletes a name.
func (s *Store) DeleteKey(vault, name string, retentionDays int) (*DeletedSecret, error) {
	if _, err := s.GetKey(vault, name); err != nil {
		return nil, err
	}
	now := s.Now()
	d := &DeletedSecret{Vault: vault, Name: name, DeletedAt: now, PurgeAt: now + int64(retentionDays)*86400}
	_, err := s.db.Exec(`INSERT INTO deleted_keys (vault, name, deleted_at, purge_at) VALUES (?,?,?,?)`,
		d.Vault, d.Name, d.DeletedAt, d.PurgeAt)
	return d, err
}

// GetDeletedKey returns the deletion record, lazily purging lapsed windows.
func (s *Store) GetDeletedKey(vault, name string) (*DeletedSecret, error) {
	d := &DeletedSecret{}
	err := s.db.QueryRow(`SELECT vault, name, deleted_at, purge_at FROM deleted_keys WHERE vault = ? AND name = ?`,
		vault, name).Scan(&d.Vault, &d.Name, &d.DeletedAt, &d.PurgeAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if s.Now() >= d.PurgeAt {
		if err := s.PurgeKey(vault, name); err != nil {
			return nil, err
		}
		return nil, ErrNotFound
	}
	return d, nil
}

// ListDeletedKeys returns unexpired deletion records.
func (s *Store) ListDeletedKeys(vault string) ([]*DeletedSecret, error) {
	rows, err := s.db.Query(`SELECT vault, name, deleted_at, purge_at FROM deleted_keys WHERE vault = ? ORDER BY name`, vault)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := s.Now()
	var out []*DeletedSecret
	var lapsed []string
	for rows.Next() {
		d := &DeletedSecret{}
		if err := rows.Scan(&d.Vault, &d.Name, &d.DeletedAt, &d.PurgeAt); err != nil {
			return nil, err
		}
		if now >= d.PurgeAt {
			lapsed = append(lapsed, d.Name)
			continue
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, name := range lapsed {
		if err := s.PurgeKey(vault, name); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// LatestKeyIncludingDeleted returns the newest version even while soft-deleted.
func (s *Store) LatestKeyIncludingDeleted(vault, name string) (*KeyVersion, error) {
	return scanKV(s.db.QueryRow(`SELECT `+kvCols+` FROM key_versions
WHERE vault = ? AND name = ? ORDER BY created_at DESC, rowid DESC LIMIT 1`, vault, name))
}

// RecoverKey undoes a soft delete.
func (s *Store) RecoverKey(vault, name string) error {
	res, err := s.db.Exec(`DELETE FROM deleted_keys WHERE vault = ? AND name = ?`, vault, name)
	if err != nil {
		return err
	}
	return oneRow(res)
}

// PurgeKey permanently removes a name.
func (s *Store) PurgeKey(vault, name string) error {
	if _, err := s.db.Exec(`DELETE FROM key_versions WHERE vault = ? AND name = ?`, vault, name); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM deleted_keys WHERE vault = ? AND name = ?`, vault, name)
	return err
}
