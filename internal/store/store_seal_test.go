package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/clock"
)

func TestSealKeyPersistsAcrossOpens(t *testing.T) {
	dir := t.TempDir()
	s1, err := Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	k1, err := s1.SealKey()
	if err != nil || len(k1) != 32 {
		t.Fatalf("SealKey = %v, %v", k1, err)
	}
	// Cached on the same store.
	if k, _ := s1.SealKey(); string(k) != string(k1) {
		t.Fatal("SealKey not cached")
	}
	_ = s1.Close()

	// A fresh open reads the same persisted key.
	s2, err := Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if k2, _ := s2.SealKey(); string(k2) != string(k1) {
		t.Fatal("SealKey not persisted across opens")
	}

	// A corrupt (short) key file is replaced.
	if err := os.WriteFile(filepath.Join(dir, "backup.key"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	s3, err := Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s3.Close() }()
	if k3, err := s3.SealKey(); err != nil || len(k3) != 32 || string(k3) == string(k1) {
		t.Fatalf("corrupt key file not regenerated: %v %v", k3, err)
	}

	// In-memory stores get an ephemeral key.
	m, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if k, err := m.SealKey(); err != nil || len(k) != 32 {
		t.Fatalf("ephemeral SealKey = %v, %v", k, err)
	}
}
