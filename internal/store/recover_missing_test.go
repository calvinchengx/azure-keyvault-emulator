package store

import (
	"testing"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/clock"
)

func TestRecoverMissingErrors(t *testing.T) {
	s, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RecoverSecret("emulator", "missing"); err == nil {
		t.Fatal("recover of a missing deleted secret succeeded")
	}
	if err := s.RecoverKey("emulator", "missing"); err == nil {
		t.Fatal("recover of a missing deleted key succeeded")
	}
	if err := s.RecoverCert("emulator", "missing"); err == nil {
		t.Fatal("recover of a missing deleted certificate succeeded")
	}
}
