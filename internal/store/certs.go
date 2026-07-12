package store

import (
	"database/sql"
	"errors"
)

// CertVersion is one immutable version of a certificate. The private key
// (PKCS#8) never leaves the store; handlers return the DER cert and derive
// the linked key/secret material.
type CertVersion struct {
	Vault      string
	Name       string
	Version    string
	CerDER     string // base64(DER) X.509
	PrivateDER string // base64(PKCS#8)
	PolicyJSON string
	Thumbprint string
	Enabled    bool
	NBF        *int64
	Exp        *int64
	TagsJSON   string
	CreatedAt  int64
	UpdatedAt  int64
}

const cvCols = `vault, name, version, cer_der, private_der, policy_json, thumbprint, enabled, nbf, exp, tags_json, created_at, updated_at`

func scanCV(row interface{ Scan(...any) error }) (*CertVersion, error) {
	v := &CertVersion{}
	err := row.Scan(&v.Vault, &v.Name, &v.Version, &v.CerDER, &v.PrivateDER, &v.PolicyJSON,
		&v.Thumbprint, &v.Enabled, &v.NBF, &v.Exp, &v.TagsJSON, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// SetCert creates a new certificate version; ErrConflict while soft-deleted.
func (s *Store) SetCert(v *CertVersion) error {
	if _, err := s.GetDeletedCert(v.Vault, v.Name); err == nil {
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
	if v.PolicyJSON == "" {
		v.PolicyJSON = "{}"
	}
	_, err := s.db.Exec(`INSERT INTO cert_versions (`+cvCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		v.Vault, v.Name, v.Version, v.CerDER, v.PrivateDER, v.PolicyJSON, v.Thumbprint,
		v.Enabled, v.NBF, v.Exp, v.TagsJSON, v.CreatedAt, v.UpdatedAt)
	return err
}

// GetCert returns the newest version of a live name.
func (s *Store) GetCert(vault, name string) (*CertVersion, error) {
	if _, err := s.GetDeletedCert(vault, name); err == nil {
		return nil, ErrNotFound
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return scanCV(s.db.QueryRow(`SELECT `+cvCols+` FROM cert_versions
WHERE vault = ? AND name = ? ORDER BY created_at DESC, rowid DESC LIMIT 1`, vault, name))
}

// GetCertVersion returns one specific version of a live name.
func (s *Store) GetCertVersion(vault, name, version string) (*CertVersion, error) {
	if _, err := s.GetDeletedCert(vault, name); err == nil {
		return nil, ErrNotFound
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return scanCV(s.db.QueryRow(`SELECT `+cvCols+` FROM cert_versions
WHERE vault = ? AND name = ? AND version = ?`, vault, name, version))
}

// ListCerts returns the newest version per live name.
func (s *Store) ListCerts(vault string) ([]*CertVersion, error) {
	rows, err := s.db.Query(`
SELECT `+cvCols+` FROM cert_versions cv
WHERE vault = ?
  AND NOT EXISTS (SELECT 1 FROM deleted_certs d WHERE d.vault = cv.vault AND d.name = cv.name)
  AND rowid = (SELECT MAX(rowid) FROM cert_versions x WHERE x.vault = cv.vault AND x.name = cv.name)
ORDER BY name`, vault)
	if err != nil {
		return nil, err
	}
	return collectCerts(rows)
}

// ListCertVersions returns all versions of a live name, oldest first.
func (s *Store) ListCertVersions(vault, name string) ([]*CertVersion, error) {
	if _, err := s.GetDeletedCert(vault, name); err == nil {
		return nil, ErrNotFound
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT `+cvCols+` FROM cert_versions
WHERE vault = ? AND name = ? ORDER BY rowid`, vault, name)
	if err != nil {
		return nil, err
	}
	return collectCerts(rows)
}

func collectCerts(rows *sql.Rows) ([]*CertVersion, error) {
	defer rows.Close()
	var out []*CertVersion
	for rows.Next() {
		v, err := scanCV(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// UpdateCertVersion applies attribute/tag changes.
func (s *Store) UpdateCertVersion(v *CertVersion) error {
	v.UpdatedAt = s.Now()
	res, err := s.db.Exec(`UPDATE cert_versions SET enabled = ?, tags_json = ?, updated_at = ?
WHERE vault = ? AND name = ? AND version = ?`, v.Enabled, v.TagsJSON, v.UpdatedAt, v.Vault, v.Name, v.Version)
	if err != nil {
		return err
	}
	return oneRow(res)
}

// ---- soft delete ----

func (s *Store) DeleteCert(vault, name string, retentionDays int) (*DeletedSecret, error) {
	if _, err := s.GetCert(vault, name); err != nil {
		return nil, err
	}
	now := s.Now()
	d := &DeletedSecret{Vault: vault, Name: name, DeletedAt: now, PurgeAt: now + int64(retentionDays)*86400}
	_, err := s.db.Exec(`INSERT INTO deleted_certs (vault, name, deleted_at, purge_at) VALUES (?,?,?,?)`,
		d.Vault, d.Name, d.DeletedAt, d.PurgeAt)
	return d, err
}

func (s *Store) GetDeletedCert(vault, name string) (*DeletedSecret, error) {
	d := &DeletedSecret{}
	err := s.db.QueryRow(`SELECT vault, name, deleted_at, purge_at FROM deleted_certs WHERE vault = ? AND name = ?`,
		vault, name).Scan(&d.Vault, &d.Name, &d.DeletedAt, &d.PurgeAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if s.Now() >= d.PurgeAt {
		if err := s.PurgeCert(vault, name); err != nil {
			return nil, err
		}
		return nil, ErrNotFound
	}
	return d, nil
}

func (s *Store) ListDeletedCerts(vault string) ([]*DeletedSecret, error) {
	rows, err := s.db.Query(`SELECT vault, name, deleted_at, purge_at FROM deleted_certs WHERE vault = ? ORDER BY name`, vault)
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
		if err := s.PurgeCert(vault, name); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) LatestCertIncludingDeleted(vault, name string) (*CertVersion, error) {
	return scanCV(s.db.QueryRow(`SELECT `+cvCols+` FROM cert_versions
WHERE vault = ? AND name = ? ORDER BY created_at DESC, rowid DESC LIMIT 1`, vault, name))
}

func (s *Store) RecoverCert(vault, name string) error {
	res, err := s.db.Exec(`DELETE FROM deleted_certs WHERE vault = ? AND name = ?`, vault, name)
	if err != nil {
		return err
	}
	return oneRow(res)
}

func (s *Store) PurgeCert(vault, name string) error {
	if _, err := s.db.Exec(`DELETE FROM cert_versions WHERE vault = ? AND name = ?`, vault, name); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM deleted_certs WHERE vault = ? AND name = ?`, vault, name)
	return err
}
