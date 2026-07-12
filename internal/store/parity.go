package store

import (
	"database/sql"
	"errors"
)

// This file holds the vault-scoped side objects the SDK manages alongside the
// versioned secret/key/cert bundles: key rotation policies, certificate
// issuers, and the per-vault certificate contacts list. Each is stored as an
// opaque JSON document — the emulator round-trips the SDK's own shape rather
// than re-deriving it.

// ---- key rotation policy (one per key name) ----

// GetKeyRotationPolicy returns the stored policy JSON, or ErrNotFound.
func (s *Store) GetKeyRotationPolicy(vault, name string) (string, error) {
	var js string
	err := s.db.QueryRow(`SELECT policy_json FROM key_rotation_policies WHERE vault = ? AND name = ?`,
		vault, name).Scan(&js)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return js, err
}

// SetKeyRotationPolicy upserts the policy JSON for a key name.
func (s *Store) SetKeyRotationPolicy(vault, name, policyJSON string) error {
	_, err := s.db.Exec(`INSERT INTO key_rotation_policies (vault, name, policy_json, updated_at)
VALUES (?,?,?,?)
ON CONFLICT(vault, name) DO UPDATE SET policy_json = excluded.policy_json, updated_at = excluded.updated_at`,
		vault, name, policyJSON, s.Now())
	return err
}

// ---- certificate issuers (many per vault) ----

// GetCertIssuer returns one issuer's JSON, or ErrNotFound.
func (s *Store) GetCertIssuer(vault, name string) (string, error) {
	var js string
	err := s.db.QueryRow(`SELECT issuer_json FROM cert_issuers WHERE vault = ? AND name = ?`,
		vault, name).Scan(&js)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return js, err
}

// SetCertIssuer upserts an issuer.
func (s *Store) SetCertIssuer(vault, name, issuerJSON string) error {
	_, err := s.db.Exec(`INSERT INTO cert_issuers (vault, name, issuer_json) VALUES (?,?,?)
ON CONFLICT(vault, name) DO UPDATE SET issuer_json = excluded.issuer_json`,
		vault, name, issuerJSON)
	return err
}

// DeleteCertIssuer removes an issuer, returning its prior JSON, or ErrNotFound.
func (s *Store) DeleteCertIssuer(vault, name string) (string, error) {
	js, err := s.GetCertIssuer(vault, name)
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(`DELETE FROM cert_issuers WHERE vault = ? AND name = ?`, vault, name)
	return js, err
}

// NamedJSON pairs an object name with its stored JSON document.
type NamedJSON struct {
	Name string
	JSON string
}

// ListCertIssuers returns every issuer in a vault, ordered by name.
func (s *Store) ListCertIssuers(vault string) ([]NamedJSON, error) {
	rows, err := s.db.Query(`SELECT name, issuer_json FROM cert_issuers WHERE vault = ? ORDER BY name`, vault)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NamedJSON
	for rows.Next() {
		var n NamedJSON
		if err := rows.Scan(&n.Name, &n.JSON); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ---- certificate contacts (one list per vault) ----

// GetCertContacts returns the vault's contacts JSON, or ErrNotFound.
func (s *Store) GetCertContacts(vault string) (string, error) {
	var js string
	err := s.db.QueryRow(`SELECT contacts_json FROM cert_contacts WHERE vault = ?`, vault).Scan(&js)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return js, err
}

// SetCertContacts upserts the vault's contacts list.
func (s *Store) SetCertContacts(vault, contactsJSON string) error {
	_, err := s.db.Exec(`INSERT INTO cert_contacts (vault, contacts_json) VALUES (?,?)
ON CONFLICT(vault) DO UPDATE SET contacts_json = excluded.contacts_json`, vault, contactsJSON)
	return err
}

// DeleteCertContacts removes the vault's contacts, returning the prior JSON.
func (s *Store) DeleteCertContacts(vault string) (string, error) {
	js, err := s.GetCertContacts(vault)
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(`DELETE FROM cert_contacts WHERE vault = ?`, vault)
	return js, err
}

// ---- pending certificates (external-issuer CSR / merge flow) ----

// PendingCert is a certificate whose key exists locally but whose signed
// certificate is awaited from an external issuer — created via a non-Self
// issuer, completed by MergeCertificate.
type PendingCert struct {
	Vault      string
	Name       string
	PrivateDER string
	CSRDER     string
	PolicyJSON string
	Kty        string
	Issuer     string
	CreatedAt  int64
}

// SetPendingCert upserts a pending certificate operation.
func (s *Store) SetPendingCert(p *PendingCert) error {
	if p.PolicyJSON == "" {
		p.PolicyJSON = "{}"
	}
	p.CreatedAt = s.Now()
	_, err := s.db.Exec(`INSERT INTO cert_pending (vault, name, private_der, csr_der, policy_json, kty, issuer, created_at)
VALUES (?,?,?,?,?,?,?,?)
ON CONFLICT(vault, name) DO UPDATE SET private_der = excluded.private_der, csr_der = excluded.csr_der,
	policy_json = excluded.policy_json, kty = excluded.kty, issuer = excluded.issuer, created_at = excluded.created_at`,
		p.Vault, p.Name, p.PrivateDER, p.CSRDER, p.PolicyJSON, p.Kty, p.Issuer, p.CreatedAt)
	return err
}

// GetPendingCert returns a pending operation, or ErrNotFound.
func (s *Store) GetPendingCert(vault, name string) (*PendingCert, error) {
	p := &PendingCert{}
	err := s.db.QueryRow(`SELECT vault, name, private_der, csr_der, policy_json, kty, issuer, created_at
FROM cert_pending WHERE vault = ? AND name = ?`, vault, name).
		Scan(&p.Vault, &p.Name, &p.PrivateDER, &p.CSRDER, &p.PolicyJSON, &p.Kty, &p.Issuer, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

// DeletePendingCert removes a pending operation (no-op if absent).
func (s *Store) DeletePendingCert(vault, name string) error {
	_, err := s.db.Exec(`DELETE FROM cert_pending WHERE vault = ? AND name = ?`, vault, name)
	return err
}

// UpdateCertPolicy replaces the policy JSON on a certificate's newest version.
func (s *Store) UpdateCertPolicy(vault, name, policyJSON string) error {
	v, err := s.GetCert(vault, name)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE cert_versions SET policy_json = ?, updated_at = ?
WHERE vault = ? AND name = ? AND version = ?`, policyJSON, s.Now(), vault, name, v.Version)
	if err != nil {
		return err
	}
	return oneRow(res)
}
