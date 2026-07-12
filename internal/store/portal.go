package store

// Vaults returns the distinct vault names that hold any object — the operator
// portal aggregates across all of them (objects are Host-routed per vault, so
// more than one can exist locally).
func (s *Store) Vaults() ([]string, error) {
	rows, err := s.db.Query(`
SELECT DISTINCT vault FROM (
	SELECT vault FROM secret_versions
	UNION SELECT vault FROM key_versions
	UNION SELECT vault FROM cert_versions
	UNION SELECT vault FROM deleted_secrets
	UNION SELECT vault FROM deleted_keys
	UNION SELECT vault FROM deleted_certs
) ORDER BY vault`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
