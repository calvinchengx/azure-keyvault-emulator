package store

import (
	"database/sql"
	"errors"
)

// SecretVersion is one immutable version of a secret.
type SecretVersion struct {
	Vault       string
	Name        string
	Version     string
	Value       string
	ContentType string
	Enabled     bool
	NBF         *int64 // nil = unset (informational attributes)
	Exp         *int64
	TagsJSON    string
	CreatedAt   int64
	UpdatedAt   int64
}

// DeletedSecret is the soft-delete record for a name.
type DeletedSecret struct {
	Vault     string
	Name      string
	DeletedAt int64
	PurgeAt   int64
}

const svCols = `vault, name, version, value, content_type, enabled, nbf, exp, tags_json, created_at, updated_at`

func scanSV(row interface{ Scan(...any) error }) (*SecretVersion, error) {
	v := &SecretVersion{}
	err := row.Scan(&v.Vault, &v.Name, &v.Version, &v.Value, &v.ContentType,
		&v.Enabled, &v.NBF, &v.Exp, &v.TagsJSON, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// SetSecret creates a new version (PUT semantics: never overwrites). Fails
// with ErrConflict while the name is soft-deleted.
func (s *Store) SetSecret(v *SecretVersion) error {
	if deleted, err := s.GetDeletedSecret(v.Vault, v.Name); err == nil && deleted != nil {
		return ErrConflict
	} else if err != nil && !errors.Is(err, ErrNotFound) {
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
	_, err := s.db.Exec(`INSERT INTO secret_versions (`+svCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		v.Vault, v.Name, v.Version, v.Value, v.ContentType, v.Enabled, v.NBF, v.Exp, v.TagsJSON, v.CreatedAt, v.UpdatedAt)
	return err
}

// GetSecret returns the newest version of a live (not soft-deleted) name.
func (s *Store) GetSecret(vault, name string) (*SecretVersion, error) {
	if _, err := s.GetDeletedSecret(vault, name); err == nil {
		return nil, ErrNotFound // soft-deleted names read as absent
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return scanSV(s.db.QueryRow(`SELECT `+svCols+` FROM secret_versions
WHERE vault = ? AND name = ? ORDER BY created_at DESC, rowid DESC LIMIT 1`, vault, name))
}

// GetSecretVersion returns one specific version of a live name.
func (s *Store) GetSecretVersion(vault, name, version string) (*SecretVersion, error) {
	if _, err := s.GetDeletedSecret(vault, name); err == nil {
		return nil, ErrNotFound
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return scanSV(s.db.QueryRow(`SELECT `+svCols+` FROM secret_versions
WHERE vault = ? AND name = ? AND version = ?`, vault, name, version))
}

// UpdateSecretVersion applies attribute/tag changes (never the value).
func (s *Store) UpdateSecretVersion(v *SecretVersion) error {
	v.UpdatedAt = s.Now()
	res, err := s.db.Exec(`UPDATE secret_versions
SET content_type = ?, enabled = ?, nbf = ?, exp = ?, tags_json = ?, updated_at = ?
WHERE vault = ? AND name = ? AND version = ?`,
		v.ContentType, v.Enabled, v.NBF, v.Exp, v.TagsJSON, v.UpdatedAt, v.Vault, v.Name, v.Version)
	if err != nil {
		return err
	}
	return oneRow(res)
}

// ListSecrets returns the newest version per live name, ordered by name.
func (s *Store) ListSecrets(vault string) ([]*SecretVersion, error) {
	rows, err := s.db.Query(`
SELECT `+svCols+` FROM secret_versions sv
WHERE vault = ?
  AND NOT EXISTS (SELECT 1 FROM deleted_secrets d WHERE d.vault = sv.vault AND d.name = sv.name)
  AND rowid = (SELECT MAX(rowid) FROM secret_versions x WHERE x.vault = sv.vault AND x.name = sv.name)
ORDER BY name`, vault)
	if err != nil {
		return nil, err
	}
	return collect(rows)
}

// ListSecretVersions returns all versions of a live name, oldest first.
func (s *Store) ListSecretVersions(vault, name string) ([]*SecretVersion, error) {
	if _, err := s.GetDeletedSecret(vault, name); err == nil {
		return nil, ErrNotFound
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT `+svCols+` FROM secret_versions
WHERE vault = ? AND name = ? ORDER BY rowid`, vault, name)
	if err != nil {
		return nil, err
	}
	return collect(rows)
}

func collect(rows *sql.Rows) ([]*SecretVersion, error) {
	defer rows.Close()
	var out []*SecretVersion
	for rows.Next() {
		v, err := scanSV(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---- soft delete ----

// DeleteSecret soft-deletes a name: versions are retained, the name becomes
// unusable, and PurgeAt is stamped from the retention window.
func (s *Store) DeleteSecret(vault, name string, retentionDays int) (*DeletedSecret, error) {
	if _, err := s.GetSecret(vault, name); err != nil {
		return nil, err
	}
	now := s.Now()
	d := &DeletedSecret{Vault: vault, Name: name, DeletedAt: now, PurgeAt: now + int64(retentionDays)*86400}
	_, err := s.db.Exec(`INSERT INTO deleted_secrets (vault, name, deleted_at, purge_at) VALUES (?,?,?,?)`,
		d.Vault, d.Name, d.DeletedAt, d.PurgeAt)
	return d, err
}

// GetDeletedSecret returns the deletion record; lapsed retention windows are
// purged lazily against the clock.
func (s *Store) GetDeletedSecret(vault, name string) (*DeletedSecret, error) {
	d := &DeletedSecret{}
	err := s.db.QueryRow(`SELECT vault, name, deleted_at, purge_at FROM deleted_secrets WHERE vault = ? AND name = ?`,
		vault, name).Scan(&d.Vault, &d.Name, &d.DeletedAt, &d.PurgeAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if s.Now() >= d.PurgeAt {
		if err := s.PurgeSecret(vault, name); err != nil {
			return nil, err
		}
		return nil, ErrNotFound
	}
	return d, nil
}

// ListDeletedSecrets returns unexpired deletion records.
func (s *Store) ListDeletedSecrets(vault string) ([]*DeletedSecret, error) {
	rows, err := s.db.Query(`SELECT vault, name, deleted_at, purge_at FROM deleted_secrets WHERE vault = ? ORDER BY name`, vault)
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
		if err := s.PurgeSecret(vault, name); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// LatestVersionIncludingDeleted returns the newest version even while the
// name is soft-deleted (deleted-secret bundles include the value id).
func (s *Store) LatestVersionIncludingDeleted(vault, name string) (*SecretVersion, error) {
	return scanSV(s.db.QueryRow(`SELECT `+svCols+` FROM secret_versions
WHERE vault = ? AND name = ? ORDER BY created_at DESC, rowid DESC LIMIT 1`, vault, name))
}

// RecoverSecret undoes a soft delete.
func (s *Store) RecoverSecret(vault, name string) error {
	res, err := s.db.Exec(`DELETE FROM deleted_secrets WHERE vault = ? AND name = ?`, vault, name)
	if err != nil {
		return err
	}
	return oneRow(res)
}

// PurgeSecret permanently removes a name: all versions and the deletion row.
func (s *Store) PurgeSecret(vault, name string) error {
	if _, err := s.db.Exec(`DELETE FROM secret_versions WHERE vault = ? AND name = ?`, vault, name); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM deleted_secrets WHERE vault = ? AND name = ?`, vault, name)
	return err
}

func oneRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
